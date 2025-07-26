<?php

namespace App\Http\Controllers;

use App\Models\AuthorizedPeople;
use App\Models\Groups;
use App\Models\StudentAuthorized;
use App\Models\Students;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class AuthorizedPeopleController extends Controller
{
    public function create(Request $request, $studentId)
    {
        $validator = Validator::make($request->all(), [
            'firstName'    => 'required|string|max:50',
            'lastName'     => 'required|string|max:50',
            'phone'        => 'required|string|max:10',
            'relationship' => 'required|string|max:50',
            'photo'        => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Datos inválidos para crear persona autorizada',
                'errors'  => $validator->errors(),
                'timestamp' => now(),
            ], 400);
        }

        $authPerson = AuthorizedPeople::create($validator->validated());

        StudentAuthorized::create([
            'studentId' => $studentId,
            'authorizedId' => $authPerson->id,
        ]);

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

        $authPerson->update(['status' => false]);

        return response()->json([
            'success' => true,
            'message' => 'Persona autorizada eliminada correctamente',
            'timestamp' => now(),
        ]);
    }

    public function myAuthorizeds($studentId)
    {
        $authorizedIds = StudentAuthorized::where('studentId', $studentId)
            ->pluck('authorizedId')
            ->toArray();

        // Obtener solo las personas autorizadas activas relacionadas con ese estudiante
        $authorizedPeoples = AuthorizedPeople::whereIn('id', $authorizedIds)
            ->where('status', true)
            ->get();

        return response()->json([
            'success' => true,
            'message' => 'Personas autorizadas del estudiante encontradas',
            'data' => $authorizedPeoples,
            'timestamp' => now(),
        ]);
    }

    public function index($schoolId)
    {
        $authorizedPeoples = AuthorizedPeople::where('status', true)->get();

        $result = $authorizedPeoples->map(function ($authPerson) use ($schoolId) {
            $studentIds = StudentAuthorized::where('authorizedId', $authPerson->id)
                ->pluck('studentId')
                ->toArray();

            // Filtrar estudiantes que pertenecen al schoolId recibido
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
        })->filter(function ($item) {
            return count($item['students']) > 0;
        })->values();

        return response()->json([
            'success' => true,
            'message' => 'Personas autorizadas y sus estudiantes relacionados en la escuela',
            'data' => $result,
            'timestamp' => now(),
        ]);
    }
}
