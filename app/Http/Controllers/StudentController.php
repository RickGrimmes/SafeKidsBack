<?php

namespace App\Http\Controllers;

use App\Models\Students;
use Illuminate\Http\Request;

class StudentController extends Controller
{
    public function create(Request $request)
    {
        
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
