<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\UserRole;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use App\Mail\ResetPasswordMail;
use App\Mail\TwoFactorAuthMail;
use App\Models\Role;
use Tymon\JWTAuth\Facades\JWTAuth;

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
                'profilePhoto' => 'required|string',
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
                } elseif ($errors->has('profilePhoto')) {
                    $msg = 'La foto es obligatoria.';
                } elseif ($errors->has('password')) {
                    $msg = 'La contraseña es obligatoria y debe tener mínimo 8 caracteres.';
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

            $creatorUser = JWTAuth::parseToken()->authenticate();
        
            if (!$creatorUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $creatorId = $creatorUser->id;

            if ($creatorId == 1)
            {
                $newUserRoleId = 2;
            } else {
                $creatorRole = UserRole::where('userId', $creatorId)->first();

                if (!$creatorRole) {
                    return response()->json([
                        'success' => false,
                        'message' => 'El usuario creador no tiene un rol asignado.',
                        'timestamp' => now(),
                    ], 400);
                }

                if ($creatorRole->roleId == 2) {
                    $newUserRoleId = 3; 
                } elseif ($creatorRole->roleId == 3) {
                    $newUserRoleId = 4; 
                } else {
                    return response()->json([
                        'success' => false,
                        'message' => 'El rol del usuario creador no es válido.',
                        'timestamp' => now(),
                    ], 400);
                }
            }

            $user = User::create([
                'firstName' => $request->firstName,
                'lastName' => $request->lastName,
                'phone' => $request->phone,
                'email' => $request->email,
                'profilePhoto' => $request->profilePhoto,
                'password' => Hash::make($request->password),
                'status' => true,
            ]);

            UserRole::create([
                'userId' => $user->id,
                'roleId' => $newUserRoleId,
                'status' => true,
                'createdBy' => $creatorId,
            ]);
    
            $creatorRole = UserRole::where('userId', $creatorId)->first();

            return response()->json([
                'success' => true,
                'message' => 'Usuario registrado correctamente',
                'data' => [
                    'createdUser' => $user->makeHidden(['password', '2facode', 'created_at']),
                    'createdUserRole' => $newUserRoleId,
                    'createdBy' => [
                        'id' => $creatorUser->id,
                        'name' => $creatorUser->firstName . ' ' . $creatorUser->lastName,
                        'email' => $creatorUser->email,
                        'role' => $creatorRole ? $creatorRole->roleId : 'Super Admin'
                    ]
                ],
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

                Mail::to($user->email)->send(new TwoFactorAuthMail($user, $code));

                return response()->json([
                    'success' => true,
                    'message' => 'Login successful',
                    'data' => $user,
                    'temporaryToken' => $temporaryToken,
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
        try {
            $requestingUser = JWTAuth::parseToken()->authenticate();
            
            if (!$requestingUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $requestingUserRole = UserRole::where('userId', $requestingUser->id)->first();
            
            if (!$requestingUserRole) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario no tiene rol asignado',
                    'timestamp' => now(),
                ], 403);
            }

            // Solo usuarios con roleId 2 (Owner) y 3 (Director) pueden consultar
            if (!in_array($requestingUserRole->roleId, [2, 3])) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para consultar usuarios',
                    'timestamp' => now(),
                ], 403);
            }

            $role = Role::where('id', $type)->first();
            
            if (!$role) {
                return response()->json([
                    'success' => false,
                    'message' => 'El tipo de rol solicitado no existe',
                    'timestamp' => now(),
                ], 404);
            }

            $userIds = UserRole::where('roleId', $type)->pluck('userId');

            if ($userIds->isEmpty()) {
                return response()->json([
                    'success' => true,
                    'message' => 'No se encontraron usuarios con el rol especificado',
                    'data' => [],
                    'timestamp' => now(),
                ], 200);
            }

            $users = User::whereIn('id', $userIds)
                ->get()
                ->makeHidden(['password', '2facode', 'created_at']);

            // Enriquecer los datos con información del rol
            $usersWithRole = $users->map(function ($user) use ($type) {
                $userRole = UserRole::where('userId', $user->id)->first();
                return [
                    'id' => $user->id,
                    'firstName' => $user->firstName,
                    'lastName' => $user->lastName,
                    'email' => $user->email,
                    'phone' => $user->phone,
                    'profilePhoto' => $user->profilePhoto,
                    'status' => $user->status,
                    'roleId' => $userRole ? $userRole->roleId : null,
                    'createdBy' => $userRole ? $userRole->createdBy : null,
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Usuarios encontrados exitosamente',
                'data' => $usersWithRole,
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar usuarios: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
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

    // actualizar contraseña

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

            $token = JWTAuth::fromUser($user);

            $userRole = UserRole::where('userId', $user->id)->first();

            return response()->json([
                'success' => true,
                'message' => 'Login completed successfully',
                'data' => $user->makeHidden(['password', '2facode', 'created_at']),
                'token' => $token,
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

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            
            return response()->json([
                'success' => true,
                'message' => 'Successfully logged out',
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to logout',
                'timestamp' => now(),
            ], 500);
        }
    }
}
