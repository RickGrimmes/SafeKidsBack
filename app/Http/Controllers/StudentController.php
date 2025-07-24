<?php

namespace App\Http\Controllers;

use App\Models\Students;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class StudentController extends Controller
{
    public function create(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:100',
                'lastName' => 'required|string|max:100',
                'birthdate' => 'required|date',
                'photo' => 'required|string',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Datos inválidos para crear estudiante',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            $student = Students::create($validator->validated());

            return response()->json([
                'success' => true,
                'message' => 'Estudiante creado exitosamente',
                'data' => $student,
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

    public function show($id) //falta mostrar también la escuela del chiquillo
    {
        try {
            $student = Students::findOrFail($id);

            return response()->json([
                'success' => true,
                'message' => 'Estudiante encontrado exitosamente',
                'data' => $student,
                'timestamp' => now(),
            ], 200);

        } catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
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
}
