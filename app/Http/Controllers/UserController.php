<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\UserRole;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use App\Mail\ResetPasswordMail;

class UserController extends Controller
{
    public function register(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:50',
                'lastName' => 'required|string|max:50',
                'phone' => 'required|string|max:10',
                'email' => 'required|email|unique:users,email',
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

            $user = User::create([
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
                'message' => 'Usuario registrado correctamente',
                'data' => $user,
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

            $user = User::where('email', $request->email)->first();

            if ($user && Hash::check($request->password, $user->password))
            {
                if (!$user->status) {
                    return response()->json([
                        'success' => false,
                        'message' => 'User is inactive',
                        'timestamp' => now(),
                    ], 403);
                }

                $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                $user->update(['2facode' => $code]);

                $temporaryToken = base64_encode(json_encode([
                    'email' => $user->email,
                    'expires_at' => now()->addMinutes(15)->timestamp,
                ]));

                Mail::to($user->email)->send(new ResetPasswordMail($user, $code));


                return response()->json([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => $user,
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

    public function index($type)
    {
        // Busca los user_ids que tengan ese roleId en user_roles
        $userIds = UserRole::where('roleId', $type)->pluck('userId');

        // Obtiene los usuarios con esos IDs y oculta campos sensibles
        $users = User::whereIn('id', $userIds)
            ->get()
            ->makeHidden(['password', '2facode', 'created_at']);

        return response()->json([
            'success' => true,
            'data' => $users,
            'timestamp' => now(),
        ], 200);
    }

    public function resetPassword(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Email is required and must be valid',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found',
                    'timestamp' => now(),
                ], 404);
            }

            $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            $user->update(['2facode' => $code]);

            Mail::to($user->email)->send(new ResetPasswordMail($user, $code));

            return response()->json([
                'success' => true,
                'message' => 'Reset password email sent',
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

    public function verify2fa(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'temporaryToken' => 'required|string',
                'code' => 'required|string|size:6',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Validation failed, emporary token and 6-digit code are required',
                    'timestamp' => now(),
                ], 400);
            }

            $tokenData = json_decode(base64_decode($request->temporaryToken), true);

            if (!$tokenData || !isset($tokenData['email'], $tokenData['expires_at'])) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid temporary token',
                    'timestamp' => now(),
                ], 400);
            }

            if (now()->timestamp > $tokenData['expires_at']) {
                return response()->json([
                    'success' => false,
                    'message' => 'Temporary token has expired',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::where('email', $tokenData['email'])->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found',
                    'timestamp' => now(),
                ], 404);
            }

            if ($user->{'2facode'} !== $request->code) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid 2FA code',
                    'timestamp' => now(),
                ], 400);
            }

            $user->update(['2facode' => null]);

            return response()->json([
                'success' => true,
                'message' => 'Login completed successfully',
                'data' => $user->makeHidden(['password', '2facode', 'created_at']),
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
}
