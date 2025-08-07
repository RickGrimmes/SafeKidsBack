<?php

namespace App\Http\Controllers;

use App\Models\AuthorizedPeople;
use App\Models\Groups;
use App\Models\Schools;
use App\Models\StudentAuthorized;
use App\Models\Students;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthorizedPeopleController extends Controller
{
    public function create(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'firstName'    => 'required|string|max:50',
            'lastName'     => 'required|string|max:50',
            'phone'        => 'required|string|max:10',
            'relationship' => 'required|string|max:50',
            'photo'        => 'required|image|mimes:jpg,jpeg,png|max:2048',
            'studentIds'   => 'required|array|min:1',
            'studentIds.*' => 'required|integer|distinct',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Datos inválidos para crear persona autorizada',
                'errors'  => $validator->errors(),
                'timestamp' => now(),
            ], 400);
        }

        $datos = $validator->validated();
        $datos['photo'] = '';
        $datos['status'] = true;

        $authPerson = AuthorizedPeople::create($datos);

        if ($request->hasFile('photo')) {
            $file = $request->file('photo');
            $firstName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $authPerson->firstName));
            $lastName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $authPerson->lastName));
            $fullName = preg_replace('/\s+/', '', $firstName . $lastName);
            $fileName = $authPerson->id . '_' . $fullName . '.jpg';
            $authPerson->photo = $fileName;
            $authPerson->save();
        }

        // Relacionar con todos los estudiantes recibidos
        foreach ($request->studentIds as $studentId) {
            StudentAuthorized::create([
                'studentId' => $studentId,
                'authorizedId' => $authPerson->id,
            ]);
        }

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada creada y relacionada correctamente',
            'data'    => $authPerson,
            'timestamp' => now(),
        ], 201);
    }

    public function show($id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada encontrada',
            'data'    => $authPerson,
            'timestamp' => now(),
        ]);
    }

    public function edit(Request $request, $id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        $validator = Validator::make($request->all(), [
            'firstName'    => 'sometimes|required|string|max:50',
            'lastName'     => 'sometimes|required|string|max:50',
            'phone'        => 'sometimes|required|string|max:10',
            'relationship' => 'sometimes|required|string|max:50',
            'photo'        => 'sometimes|required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Datos inválidos para editar persona autorizada',
                'errors'  => $validator->errors(),
                'timestamp' => now(),
            ], 400);
        }

        $authPerson->update($validator->validated());

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada actualizada correctamente',
            'data'    => $authPerson,
            'timestamp' => now(),
        ]);
    }

    public function delete($id)
    {
        $authPerson = AuthorizedPeople::find($id);

        if (!$authPerson) {
            return response()->json([
                'success' => false,
                'message' => 'Persona autorizada no encontrada',
                'timestamp' => now(),
            ], 404);
        }

        $studentAuthorized = StudentAuthorized::where('authorizedId', $authPerson->id)->first();
        $schoolInfo = null;
        if ($studentAuthorized) {
            $group = Groups::where('studentId', $studentAuthorized->studentId)->first();
            if ($group) {
                $school = Schools::find($group->schoolId);
                if ($school) {
                    $schoolInfo = [
                        'id' => $school->id,
                        'name' => $school->name,
                        'address' => $school->address,
                        'phone' => $school->phone,
                        'city' => $school->city,
                        'status' => $school->status
                    ];
                }
            }
        }

        $authPerson->update(['status' => false]);

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada eliminada correctamente',
            'data' => [
                'authorized_id' => $authPerson->id,
                'status' => $authPerson->status,
                'role_type' => 'AUTHORIZED_PEOPLE',
                'school' => $schoolInfo
            ],
            'timestamp' => now(),
        ]);
    }

    public function myAuthorizeds($studentId)
    {
        $group = Groups::where('studentId', $studentId)->first();
        $schoolId = $group ? $group->schoolId : null;

        $authorizedIds = StudentAuthorized::where('studentId', $studentId)
            ->pluck('authorizedId')
            ->toArray();

        $authorizedPeoples = AuthorizedPeople::whereIn('id', $authorizedIds)
            ->where('status', true)
            ->get();

        $authorizedWithExtras = $authorizedPeoples->map(function ($authPerson) use ($schoolId) {
            $data = $authPerson->makeHidden(['created_at']);
            $data['school_id'] = $schoolId;
            $data['img_route'] = $schoolId . '/AUTHORIZEDS/' . $authPerson->photo;
            return $data;
        });

        return response()->json([
            'success' => true,
            'message' => 'Personas autorizadas del estudiante encontradas',
            'data' => $authorizedWithExtras,
            'timestamp' => now(),
        ]);
    }

    public function index($schoolId, $studentId = 'ALL')
    {
        $authorizedPeoples = AuthorizedPeople::where('status', true)->get();

        $result = $authorizedPeoples->map(function ($authPerson) use ($schoolId, $studentId) {
            $studentIds = StudentAuthorized::where('authorizedId', $authPerson->id)
                ->pluck('studentId')
                ->toArray();

            if ($studentId !== 'ALL') {
                if (!in_array($studentId, $studentIds)) {
                    return null;
                }
                $studentIds = [$studentId];
            }

            $students = Students::whereIn('id', $studentIds)
                ->where('status', true)
                ->get(['id', 'firstName', 'lastName'])
                ->filter(function ($student) use ($schoolId) {
                    $group = Groups::where('studentId', $student->id)
                        ->where('schoolId', $schoolId)
                        ->first();
                    return $group !== null;
                })
                ->map(function ($student) use ($schoolId) {
                    $group = Groups::where('studentId', $student->id)
                        ->where('schoolId', $schoolId)
                        ->first();
                    return [
                        'id' => $student->id,
                        'firstName' => $student->firstName,
                        'lastName' => $student->lastName,
                        'gradeSection' => $group ? $group->gradeSection : null,
                    ];
                })
                ->values();

            return [
                'authorized_person' => $authPerson,
                'students' => $students,
            ];
        })
        ->filter(function ($item) {
            return $item && count($item['students']) > 0;
        })
        ->values();

        return response()->json([
            'success' => true,
            'message' => 'Personas autorizadas y sus estudiantes relacionados en la escuela',
            'data' => $result,
            'timestamp' => now(),
        ]);
    }
}
