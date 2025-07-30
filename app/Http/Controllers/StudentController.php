<?php

namespace App\Http\Controllers;

use App\Models\Groups;
use App\Models\GuardiansSchool;
use App\Models\Schools;
use App\Models\StudentGuardian;
use App\Models\Students;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class StudentController extends Controller
{
    public function create(Request $request, $schoolId) 
    {
        try {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:100',
                'lastName' => 'required|string|max:100',
                'birthDate' => 'required|date',
                'photo' => 'required|image|mimes:jpg,jpeg,png|max:2048',
                'gradeSection' => 'required|string|max:50',
                'guardianIds' => 'required|array|min:1|max:2',
                'guardianIds.*' => 'required|integer|distinct',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Datos inválidos para crear estudiante',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            // Validar que los guardianes tengan relación con la escuela
            $guardianIds = $request->guardianIds;
            $validGuardians = GuardiansSchool::whereIn('guardian_id', $guardianIds)
                ->where('school_id', $schoolId)
                ->pluck('guardian_id')
                ->toArray();

            if (count($validGuardians) !== count($guardianIds)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Solo puedes asignar tutores que estén relacionados con esta escuela',
                    'timestamp' => now(),
                ], 400);
            }

            // Crear el estudiante
            $student = Students::create([
                'firstName' => $request->firstName,
                'lastName' => $request->lastName,
                'birthDate' => $request->birthDate,
                'photo' => '',
                'gradeSection' => $request->gradeSection,
                'status' => true,
            ]);

            // Procesar la imagen
            if ($request->hasFile('photo')) {
                $file = $request->file('photo');
                $firstName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $student->firstName));
                $lastName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $student->lastName));
                $fullName = preg_replace('/\s+/', '', $firstName . $lastName);
                $fileName = $student->id . '_' . $fullName . '.jpg';
                $student->photo = $fileName;
                $student->save();
            }

            // Crear el grupo
            $group = Groups::create([
                'studentId' => $student->id,
                'schoolId' => $schoolId,
                'gradeSection' => $request->gradeSection,
            ]);

            // Crear la relación student_guardian
            foreach ($guardianIds as $guardianId) {
                StudentGuardian::create([
                    'studentId' => $student->id,
                    'guardianId' => $guardianId,
                ]);
            }

            return response()->json([
                'success' => true,
                'message' => 'Estudiante, grupo y tutores asignados exitosamente',
                'data' => [
                    'student' => $student,
                    'group' => $group,
                    'guardians' => $guardianIds,
                ],
                'timestamp' => now(),
            ], 201);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al crear estudiante: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function show($id)
    {
        try {
            $student = Students::where('id', $id)->where('status', true)->firstOrFail();

            $group = Groups::where('studentId', $student->id)->first();
            $schoolName = null;

            if ($group) {
                $school = Schools::find($group->schoolId);
                if ($school) {
                    $schoolName = $school->name;
                }
            }

            return response()->json([
                'success' => true,
                'message' => 'Estudiante encontrado exitosamente',
                'data' => [
                    'student' => $student,
                    'school_name' => $schoolName,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Estudiante no encontrado',
                'timestamp' => now(),
            ], 404);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar estudiante: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function index($schoolId, $filter = 'All')
    {
        try {
            $students = Students::where('status', true)
                ->whereHas('groups', function ($q) use ($schoolId, $filter) {
                    $q->where('schoolId', $schoolId);
                    if ($filter !== 'All') {
                        $q->where('gradeSection', $filter);
                    }
                })->get();

            $studentsWithGrade = $students->map(function ($student) use ($schoolId) {
                $group = Groups::where('studentId', $student->id)
                    ->where('schoolId', $schoolId)
                    ->first();
                return [
                    'student' => $student,
                    'gradeSection' => $group ? $group->gradeSection : null,
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Estudiantes encontrados exitosamente',
                'data' => $studentsWithGrade,
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar estudiantes: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function editGroup(Request $request, $studentId)
    {
        try {
            $validator = Validator::make($request->all(), [
                'gradeSection' => 'required|string|max:50',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Datos inválidos para editar grupo',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            $student = Students::findOrFail($studentId);
            $group = Groups::where('studentId', $student->id)->first();

            if (!$group) {
                return response()->json([
                    'success' => false,
                    'message' => 'Grupo no encontrado para el estudiante',
                    'timestamp' => now(),
                ], 404);
            }

            $group->update(['gradeSection' => $request->gradeSection]);

            return response()->json([
                'success' => true,
                'message' => 'Grupo actualizado exitosamente',
                'data' => [
                    'student' => $student,
                    'gradeSection' => $group->gradeSection,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Estudiante no encontrado',
                'timestamp' => now(),
            ], 404);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al editar grupo: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function delete($id)
    {
        try {
            $student = Students::findOrFail($id);

            $student->update(['status' => false]);

            return response()->json([
                'success' => true,
                'message' => 'Estudiante dado de baja correctamente',
                'data' => [
                    'student_id' => $student->id,
                    'status' => $student->status,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Estudiante no encontrado',
                'timestamp' => now(),
            ], 404);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al dar de baja estudiante: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }
}
