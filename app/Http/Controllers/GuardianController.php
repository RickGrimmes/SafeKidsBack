<?php

namespace App\Http\Controllers;

use App\Models\Guardians;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class GuardianController extends Controller
{
    public function register(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:50',
                'lastName' => 'required|string|max:50',
                'phone' => 'required|string|max:10',
                'email' => 'required|email|unique:guardians,email',
                'photo' => 'required|string',
                'password' => 'required|string|min:8',
            ]);
            
            if ($validator->fails()) {
                $errors = $validator->errors();
                if ($errors->has('firstName')) {
                    $msg = 'El nombre es obligatorio y debe tener máximo 50 caracteres.';
                } elseif ($errors->has('lastName')) {
                    $msg = 'El apellido es obligatorio y debe tener máximo 50 caracteres.';
                } elseif ($errors->has('phone')) {
                    $msg = 'El teléfono es obligatorio y debe tener máximo 10 dígitos.';
                } elseif ($errors->has('email')) {
                    $msg = 'El correo es obligatorio, debe ser válido y único.';
                } elseif ($errors->has('photo')) {
                    $msg = 'La foto es obligatoria.';
                } elseif ($errors->has('password')) {
                    $msg = 'La contraseña es obligatoria y debe tener mínimo 8 caracteres.';
                } else {
                    $msg = 'Datos inválidos.';
                }
                return response()->json([
                    'success' => false,
                    'message' => $msg,
                    'errors' => $errors,
                    'timestamp' => now(),
                ], 400);
            }

            $guardians = Guardians::create([
                'firstName' => $request->firstName,
                'lastName' => $request->lastName,
                'phone' => $request->phone,
                'email' => $request->email,
                'photo' => $request->photo,
                'password' => Hash::make($request->password),
                'status' => true,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Tutor registrado correctamente',
                'data' => $guardians,
                'timestamp' => now(),
            ], 200);
        }
        catch (\Exception $e)
        {
            return response()->json([
                    'success' => false,
                    'message' => 'Server failed',
                    'timestamp' => now(),
            ], 500);
        }
    }

    public function login(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:8',
            ]);

            if ($validator->fails())
            {
                return response()->json([
                    'success' => false,
                    'message' => 'Validation failed',
                    'timestamp' => now(),
                ], 400);
            }

            $guardians = Guardians::where('email', $request->email)->first();

            if ($guardians && Hash::check($request->password, $guardians->password))
            {
                if (!$guardians->status) {
                    return response()->json([
                        'success' => false,
                        'message' => 'Guardians is inactive',
                        'timestamp' => now(),
                    ], 403);
                }

                return response()->json([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => $guardians,
                    'timestamp' => now(),
                ], 200);
            }
            else
            {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid credentials',
                    'timestamp' => now(),
                ], 401);
            }
        }
        catch (\Exception $e)
        {
            return response()->json([
                'success' => false,
                'message' => 'Login failed',
                'timestamp' => now(),
            ], 400);
        }
    }

    public function show($id)
    {
        $guardian = Guardians::find($id);

        if (!$guardian) {
            return response()->json([
                'success' => false,
                'message' => 'Guardian not found',
                'timestamp' => now(),
            ], 404);
        }

        $data = $guardian->makeHidden(['2facode', 'password', 'created_at']);

        return response()->json([
            'success' => true,
            'data' => $data,
            'timestamp' => now(),
        ], 200);
    }
}
