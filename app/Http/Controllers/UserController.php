<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\UserRole;
use App\Models\Schools;
use App\Models\SchoolUsers;
use App\Models\SchoolTypes;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Mail;
use App\Mail\ResetPasswordMail;
use App\Mail\TwoFactorAuthMail;
use App\Models\Role;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
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
                'profilePhoto' => 'required|image|mimes:jpg,jpeg,png|max:2048',
                'password' => 'required|string|min:8',
                'school_id' => 'sometimes|integer|exists:schools,id',
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

            DB::beginTransaction();

            try {
                // 1. Crear usuario
                $user = User::create([
                    'firstName' => $request->firstName,
                    'lastName' => $request->lastName,
                    'phone' => $request->phone,
                    'email' => $request->email,
                    'profilePhoto' => '', 
                    'password' => Hash::make($request->password),
                    'status' => true,
                ]);

                // 2. Actualizar foto
                if ($request->hasFile('profilePhoto')) {
                    $file = $request->file('profilePhoto');
                    $firstName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $user->firstName));
                    $lastName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $user->lastName));
                    $fullName = preg_replace('/\s+/', '', $firstName . $lastName);
                    $fileName = $user->id . '_' . $fullName . '.jpg';
                    $user->profilePhoto = $fileName;
                    $user->save();
                }

                // 3. Crear UserRole
                $userRole = UserRole::create([
                    'userId' => $user->id,
                    'roleId' => $newUserRoleId,
                    'status' => true,
                    'createdBy' => $creatorId,
                ]);

                // 4. DEBUG: Log para verificar
                Log::info('Usuario y UserRole creados', [
                    'user_id' => $user->id,
                    'user_role_id' => $userRole->id,
                    'role_id' => $newUserRoleId,
                    'school_id_received' => $request->school_id ?? 'No recibido'
                ]);

                // 5. Si es director y viene school_id, crear registro en school_users
                if ($newUserRoleId == 3 && $request->has('school_id')) {
                    
                    // Validar que la escuela existe y está activa
                    $school = Schools::where('id', $request->school_id)
                        ->where('status', true)
                        ->first();
                    
                    if (!$school) {
                        throw new \Exception("La escuela con ID {$request->school_id} no existe o está inactiva");
                    }

                    // Validar que el creador tiene acceso a esta escuela
                    $creatorUserRole = UserRole::where('userId', $creatorId)->first();
                    $ownerHasAccess = SchoolUsers::where('schoolId', $request->school_id)
                        ->where('userRoleId', $creatorUserRole->id)
                        ->exists();
                    
                    if (!$ownerHasAccess) {
                        throw new \Exception("No tienes acceso a la escuela con ID {$request->school_id}");
                    }

                    // Crear el registro en school_users
                    $schoolUser = SchoolUsers::create([
                        'schoolId' => $request->school_id,
                        'userRoleId' => $userRole->id
                    ]);

                    Log::info('SchoolUser creado', [
                        'school_user_id' => $schoolUser->id,
                        'school_id' => $request->school_id,
                        'user_role_id' => $userRole->id
                    ]);
                }

                DB::commit();

                $creatorRole = UserRole::where('userId', $creatorId)->first();

                return response()->json([
                    'success' => true,
                    'message' => 'Usuario registrado correctamente' . ($newUserRoleId == 3 && $request->has('school_id') ? ' y asignado a la escuela' : ''),
                    'data' => [
                        'createdUser' => $user->makeHidden(['password', '2facode', 'created_at']),
                        'createdUserRole' => $newUserRoleId,
                        'assignedToSchool' => $newUserRoleId == 3 && $request->has('school_id') ? $request->school_id : null,
                        'createdBy' => [
                            'id' => $creatorUser->id,
                            'name' => $creatorUser->firstName . ' ' . $creatorUser->lastName,
                            'email' => $creatorUser->email,
                            'role' => $creatorRole ? $creatorRole->roleId : 'Super Admin'
                        ]
                    ],
                    'timestamp' => now(),
                ], 200);

            } catch (\Exception $e) {
                DB::rollback();
                Log::error('Error en register()', [
                    'error' => $e->getMessage(),
                    'school_id' => $request->school_id ?? 'No recibido',
                    'new_user_role_id' => $newUserRoleId ?? 'No definido'
                ]);
                throw $e;
            }

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Server failed: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function registerOwner(Request $request)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:50',
                'lastName' => 'required|string|max:50',
                'phone' => 'required|string|max:10',
                'email' => 'required|email|unique:users,email',
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
                return response()->json([
                    'success' => false,
                    'message' => 'El rol del usuario creador no es válido.',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::create([
                'firstName' => $request->firstName,
                'lastName' => $request->lastName,
                'phone' => $request->phone,
                'email' => $request->email,
                'profilePhoto' => '', 
                'password' => Hash::make($request->password),
                'status' => true,
            ]);

            $firstName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $user->firstName));
            $lastName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $user->lastName));
            $fullName = preg_replace('/\s+/', '', $firstName . $lastName);
            $fileName = $user->id . '_' . $fullName . '.jpg';
            $user->profilePhoto = $fileName;
            $user->save();

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

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Fallo la validacion.',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::where('email', $request->email)->first();

            if ($user && Hash::check($request->password, $user->password))
            {
                if (!$user->status) {
                    return response()->json([
                        'success' => false,
                        'message' => 'El usuario está inactivo.',
                        'timestamp' => now(),
                    ], 403);
                }

                $userAgent = $request->header('User-Agent');
                $isMobile = preg_match('/Mobile|Android|iPhone|iPad|iPod/i', $userAgent);

                $userRole = UserRole::where('userId', $user->id)->first();

                if ($userRole) {

                  if (!in_array($userRole->roleId, [2, 3])) {
                        return response()->json([
                            'success' => false,
                            'message' => 'Usuario no autorizado',
                            'timestamp' => now(),
                        ], 403);
                    }


                    if ($userRole->roleId == 4 && !$isMobile) {
                        return response()->json([
                            'success' => false,
                            'message' => 'Usuario no autorizado',
                            'timestamp' => now(),
                        ], 403);
                    }
                }

                $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
                $user->update(['2facode' => $code]);

                $temporaryToken = base64_encode(json_encode([
                    'email' => $user->email,
                    'expires_at' => now()->addMinutes(15)->timestamp
                ]));

                Mail::to($user->email)->send(new TwoFactorAuthMail($user, $code));

                return response()->json([
                    'sucess' => true,
                    'message' => 'Código de autenticación enviado al correo electrónico',
                    'data' => $user,
                    'temporaryToken' => $temporaryToken,
                    'timestamp' => now(),
                ], 200);
            }
            else
            {
                return response()->json([
                    'success' => false,
                    'message' => 'Credenciales incorrectas',
                    'timestamp' => now(),
                ], 401);
            }
        }
        catch (\Exception $e)
        {
            return response()->json([
                'success' => false,
                'message' => 'Login fallido',
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

            if ($requestingUserRole->roleId == 2) {
                if ($type != 3) {
                    return response()->json([
                        'success' => false,
                        'message' => 'No puedes ver otro tipo de usuario',
                        'timestamp' => now(),
                    ], 403);
                }
            } elseif ($requestingUserRole->roleId == 3) {
                if ($type != 4) {
                    return response()->json([
                        'success' => false,
                        'message' => 'No puedes ver otro tipo de usuario',
                        'timestamp' => now(),
                    ], 403);
                }
            } else {
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

            $userRoles = UserRole::where('roleId', $type)
                ->where('createdBy', $requestingUser->id)
                ->get();

            if ($userRoles->isEmpty()) {
                return response()->json([
                    'success' => true,
                    'message' => 'No has creado usuarios con el rol especificado',
                    'data' => [],
                    'role_info' => [
                        'id' => $role->id,
                        'name' => $role->name ?? "Rol $type"
                    ],
                    'requesting_user' => [
                        'id' => $requestingUser->id,
                        'name' => $requestingUser->firstName . ' ' . $requestingUser->lastName,
                        'role' => $requestingUserRole->roleId
                    ],
                    'timestamp' => now(),
                ], 200);
            }

            $userIds = $userRoles->pluck('userId');

            $users = User::whereIn('id', $userIds)
                ->where('status', true)
                ->get()
                ->makeHidden(['password', '2facode', 'created_at']);

            $usersWithRole = $users->map(function ($user) use ($userRoles) {
                $userRole = $userRoles->where('userId', $user->id)->first();

                $schoolUser = SchoolUsers::where('userRoleId', $userRole->id)->first();
                $school = null;
                if ($schoolUser) {
                    $schoolModel = Schools::where('id', $schoolUser->schoolId)->where('status', true)->first();
                    if ($schoolModel) {
                        $schoolTypes = $schoolModel->schoolTypes->map(function ($schoolType) {
                            return [
                                'id' => $schoolType->id,
                                'type' => $schoolType->type,
                                'type_name' => $this->getSchoolTypeName($schoolType->type)
                            ];
                        });
                        $school = [
                            'id' => $schoolModel->id,
                            'name' => $schoolModel->name,
                            'address' => $schoolModel->address,
                            'phone' => $schoolModel->phone,
                            'city' => $schoolModel->city,
                            'status' => $schoolModel->status,
                            'school_types' => $schoolTypes,
                            'total_types' => $schoolTypes->count(),
                            'school_user_id' => $schoolUser->id
                        ];
                    }
                }

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
                    'userRoleId' => $userRole ? $userRole->id : null,
                    'userRoleStatus' => $userRole ? $userRole->status : null,
                    'school' => $school
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Usuarios creados por ti encontrados exitosamente',
                'data' => $usersWithRole,
                'total_users' => $users->count(),
                'role_info' => [
                    'id' => $role->id,
                    'name' => $role->name ?? "Rol $type"
                ],
                'requesting_user' => [
                    'id' => $requestingUser->id,
                    'name' => $requestingUser->firstName . ' ' . $requestingUser->lastName,
                    'role' => $requestingUserRole->roleId
                ],
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
                    'message' => 'El correo es obligatorio y debe ser válido',
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
                'message' => 'Correo de restablecimiento de contraseña enviado',
                'data' => $user->email,
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

    public function passwordChallenge(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'code' => 'required|string|size:6',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'El código de 6 dígitos es obligatorio',
                    'timestamp' => now(),
                ], 400);
            }

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'El código de 6 dígitos es obligatorio',
                'timestamp' => now(),
            ], 400);
        }

        $user = User::where('2facode', $request->code)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'Código inválido o expirado',
                'timestamp' => now(),
            ], 400);
        }

        $temporaryToken = base64_encode(json_encode([
            'user_id' => $user->id,
            'email' => $user->email,
            'purpose' => 'password_reset',
            'expires_at' => now()->addMinutes(15)->timestamp,
            'verification_code' => $request->code
        ]));

        return response()->json([
            'success' => true,
            'message' => 'Código verificado correctamente',
            'data' => [
                'user_id' => $user->id,
                'email' => $user->email,
                'firstName' => $user->firstName,
                'lastName' => $user->lastName
            ],
            'resetToken' => $temporaryToken,
            'timestamp' => now(),
        ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al verificar código: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function changePassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'resetToken' => 'required|string',
                'password' => 'required|string|min:8',
            ]);

            if ($validator->fails()) {
                $errors = $validator->errors();
                if ($errors->has('password')) {
                    $msg = 'La nueva contraseña es obligatoria y debe tener mínimo 8 caracteres.';
                } elseif ($errors->has('resetToken')) {
                    $msg = 'Token de reset es obligatorio.';
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

            // Decodificar y validar el token temporal
            $tokenData = json_decode(base64_decode($request->resetToken), true);

            if (!$tokenData || !isset($tokenData['user_id'], $tokenData['expires_at'], $tokenData['purpose'])) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token de reset inválido',
                    'timestamp' => now(),
                ], 400);
            }

            // Verificar que el token sea para reset de contraseña
            if ($tokenData['purpose'] !== 'password_reset') {
                return response()->json([
                    'success' => false,
                    'message' => 'Token no válido para cambio de contraseña',
                    'timestamp' => now(),
                ], 400);
            }

            // Verificar que el token no haya expirado
            if (now()->timestamp > $tokenData['expires_at']) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token de reset ha expirado',
                    'timestamp' => now(),
                ], 400);
            }

            // Buscar el usuario
            $user = User::find($tokenData['user_id']);

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            // Validar que el código de verificación aún coincida (seguridad extra)
            if (isset($tokenData['verification_code']) && $user->{'2facode'} !== $tokenData['verification_code']) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token de reset inválido o ya utilizado',
                    'timestamp' => now(),
                ], 400);
            }

            // Actualizar la contraseña y limpiar el código 2FA
            $user->update([
                'password' => Hash::make($request->password),
                '2facode' => null 
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Contraseña actualizada exitosamente',
                'data' => [
                    'user_id' => $user->id,
                    'email' => $user->email,
                    'firstName' => $user->firstName,
                    'lastName' => $user->lastName,
                    'password_changed_at' => now()
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al cambiar contraseña: ' . $e->getMessage(),
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
                    'message' => 'Validación fallida. El token temporal y el código de 2FA son obligatorios.',
                    'timestamp' => now(),
                ], 400);
            }

            $tokenData = json_decode(base64_decode($request->temporaryToken), true);

            if (!$tokenData || !isset($tokenData['email'], $tokenData['expires_at'])) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token temporal inválido',
                    'timestamp' => now(),
                ], 400);
            }

            if (now()->timestamp > $tokenData['expires_at']) {
                return response()->json([
                    'success' => false,
                    'message' => 'El token temporal ha expirado',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::where('email', $tokenData['email'])->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            if ($user->{'2facode'} !== $request->code) {
                return response()->json([
                    'success' => false,
                    'message' => 'Código de 2FA inválido',
                    'timestamp' => now(),
                ], 400);
            }

            $user->update(['2facode' => null]);

            $token = JWTAuth::fromUser($user);

            // Obtener el rol del usuario
            $userRole = UserRole::where('userId', $user->id)->first();

            // Obtener la escuela (si tiene asignación en school_users)
            $schoolUser = $userRole ? SchoolUsers::where('userRoleId', $userRole->id)->first() : null;
            $school = null;
            if ($schoolUser) {
                $schoolModel = Schools::where('id', $schoolUser->schoolId)->where('status', true)->first();
                if ($schoolModel) {
                    $schoolTypes = $schoolModel->schoolTypes->map(function ($schoolType) {
                        return [
                            'id' => $schoolType->id,
                            'type' => $schoolType->type,
                            'type_name' => $this->getSchoolTypeName($schoolType->type)
                        ];
                    });
                    $school = [
                        'id' => $schoolModel->id,
                        'name' => $schoolModel->name,
                        'address' => $schoolModel->address,
                        'phone' => $schoolModel->phone,
                        'city' => $schoolModel->city,
                        'status' => $schoolModel->status,
                        'school_types' => $schoolTypes,
                        'total_types' => $schoolTypes->count(),
                        'school_user_id' => $schoolUser->id
                    ];
                }
            }

            return response()->json([
                'success' => true,
                'message' => 'Login completado con éxito',
                'data' => $user->makeHidden(['password', '2facode', 'created_at']),
                'school' => $school,
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

    public function resend2fa(Request $request) 
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'El correo es obligatorio y debe ser válido',
                    'timestamp' => now(),
                ], 400);
            }

            $user = User::where('email', $request->email)->first();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $user->update(['2facode' => $code]);

            Mail::to($user->email)->send(new TwoFactorAuthMail($user, $code));

            return response()->json([
                'success' => true,
                'message' => 'Código de autenticación reenviado al correo',
                'data' => $user->email,
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al reenviar código: ' . $e->getMessage(),
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
                'message' => 'Logout exitoso',
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Falló el cierre de sesión',
                'timestamp' => now(),
            ], 500);
        }
    }

    public function myDirectors()
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario no tiene rol asignado',
                    'timestamp' => now(),
                ], 403);
            }

            if ($userRole->roleId !== 2) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para consultar esta información.',
                    'timestamp' => now(),
                ], 403);
            }

            $directorRoles = UserRole::where('roleId', 3)
                ->where('createdBy', $authenticatedUser->id)
                ->get();

            if ($directorRoles->isEmpty()) {
                return response()->json([
                    'success' => true,
                    'message' => 'No has creado ningún director aún',
                    'data' => [],
                    'owner_info' => [
                        'id' => $authenticatedUser->id,
                        'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                        'email' => $authenticatedUser->email
                    ],
                    'timestamp' => now(),
                ], 200);
            }

            $directorIds = $directorRoles->pluck('userId');

            $directors = User::whereIn('id', $directorIds)
                ->where('status', true) 
                ->select('id', 'firstName', 'lastName', 'email', 'phone', 'profilePhoto', 'status')
                ->get();

            $directorsWithoutSchool = $directors->filter(function ($director) use ($directorRoles) {
                $directorRole = $directorRoles->where('userId', $director->id)->first();
                if (!$directorRole) return false;
                // Verifica si NO tiene ningún registro en school_users
                $hasSchool = SchoolUsers::where('userRoleId', $directorRole->id)->exists();
                return !$hasSchool;
            })->values();

            return response()->json([
                'success' => true,
                'message' => 'Directores y sus escuelas asignadas encontrados exitosamente',
                'data' => $directorsWithoutSchool,
                'total_directors' => $directorsWithoutSchool->count(),
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar directores: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }
    
    public function myDirectorsOld()
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $authenticatedUser->id)->first();
            
            if (!$userRole) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario no tiene rol asignado',
                    'timestamp' => now(),
                ], 403);
            }

            if ($userRole->roleId !== 2) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para consultar esta información.',
                    'timestamp' => now(),
                ], 403);
            }

            $directorRoles = UserRole::where('roleId', 3)
                ->where('createdBy', $authenticatedUser->id)
                ->get();

            if ($directorRoles->isEmpty()) {
                return response()->json([
                    'success' => true,
                    'message' => 'No has creado ningún director aún',
                    'data' => [],
                    'owner_info' => [
                        'id' => $authenticatedUser->id,
                        'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                        'email' => $authenticatedUser->email
                    ],
                    'timestamp' => now(),
                ], 200);
            }

            $directorIds = $directorRoles->pluck('userId');

            $directors = User::whereIn('id', $directorIds)
                ->where('status', true) 
                ->select('id', 'firstName', 'lastName', 'email', 'phone', 'profilePhoto', 'status')
                ->get();

            // Formatear la respuesta con información adicional del rol y escuelas
            $directorsData = $directors->map(function ($director) use ($directorRoles) {
                $directorRole = $directorRoles->where('userId', $director->id)->first();
                
                // Buscar las escuelas donde este director está asignado
                $schoolUsers = SchoolUsers::where('userRoleId', $directorRole->id)->get();
                
                $schools = [];
                if ($schoolUsers->isNotEmpty()) {
                    $schoolIds = $schoolUsers->pluck('schoolId');
                    
                    $schoolsData = Schools::whereIn('id', $schoolIds)
                        ->where('status', true) 
                        ->with(['schoolTypes'])
                        ->get();
                    
                    $schools = $schoolsData->map(function ($school) use ($schoolUsers, $directorRole) {
                        // Encontrar el registro school_user específico
                        $schoolUser = $schoolUsers->where('schoolId', $school->id)->first();
                        
                        // Obtener tipos de escuela con nombres legibles
                        $types = $school->schoolTypes->map(function ($schoolType) {
                            return [
                                'id' => $schoolType->id,
                                'type' => $schoolType->type,
                                'type_name' => $this->getSchoolTypeName($schoolType->type)
                            ];
                        });
                        
                        return [
                            'school_id' => $school->id,
                            'school_name' => $school->name,
                            'school_address' => $school->address,
                            'school_phone' => $school->phone,
                            'school_city' => $school->city,
                            'school_status' => $school->status,
                            'school_types' => $types,
                            'total_types' => $types->count(),
                            'school_user_id' => $schoolUser ? $schoolUser->id : null,
                            'assigned_at' => $school->created_at
                        ];
                    });
                }
                
                return [
                    'director_info' => [
                        'id' => $director->id,
                        'firstName' => $director->firstName,
                        'lastName' => $director->lastName,
                        'fullName' => $director->firstName . ' ' . $director->lastName,
                        'email' => $director->email,
                        'phone' => $director->phone,
                        'profilePhoto' => $director->profilePhoto,
                        'status' => $director->status,
                    ],
                    'assigned_schools' => $schools,
                ];
            });

            return response()->json([
                'success' => true,
                'message' => 'Directores y sus escuelas asignadas encontrados exitosamente',
                'data' => $directorsData,
                'total_directors' => $directors->count(),
                'summary' => [
                    'directors_with_schools' => $directorsData->where('has_schools', true)->count(),
                    'directors_without_schools' => $directorsData->where('has_schools', false)->count(),
                    'total_school_assignments' => $directorsData->sum('total_schools')
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar directores: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    // Método helper para los nombres de tipos de escuela
    private function getSchoolTypeName($type)
    {
        $names = [
            'kindergarten' => 'Jardín de Niños',
            'day_care' => 'Guardería',
            'preschool' => 'Preescolar'
        ];
        
        return $names[$type] ?? $type;
    }

    public function myProfile()
    {
        try {
            $user = JWTAuth::parseToken()->authenticate();
            
            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userRole = UserRole::where('userId', $user->id)->first();

            if (!$userRole) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario no tiene rol asignado',
                    'timestamp' => now(),
                ], 403);
            }

            $schoolUser = SchoolUsers::where('userRoleId', $userRole->id)->first();
            $schoolId = $schoolUser ? $schoolUser->schoolId : null;

            // Construir IMG_ROUTE
            $roleNameUpper = strtoupper($userRole->role->name ?? "Rol {$userRole->roleId}");
            $profilePhoto = $user->profilePhoto;
            $imgRoute = $schoolId . '/' . $roleNameUpper . '/' . $profilePhoto;

            return response()->json([
                'success' => true,
                'message' => 'Perfil del usuario obtenido exitosamente',
                'data' => $user->makeHidden(['password', '2facode', 'created_at']),
                'role_info' => [
                    'id' => $userRole->roleId,
                    'name' => $roleNameUpper
                ],
                'school_id' => $schoolId,
                'img_route' => $imgRoute,
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al obtener perfil: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function edit(Request $request, $id)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email|unique:users,email,' . $id,
                'phone' => 'required|string|max:10',
            ]);

            if ($validator->fails()) {
                $errors = $validator->errors();
                if ($errors->has('email')) {
                    $msg = 'El correo es obligatorio, debe ser válido y único.';
                } elseif ($errors->has('phone')) {
                    $msg = 'El teléfono es obligatorio y debe tener máximo 10 dígitos.';
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

            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userToEdit = User::find($id);
            
            if (!$userToEdit) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $userRoleToEdit = UserRole::where('userId', $id)
                ->where('createdBy', $authenticatedUser->id)
                ->first();

            if (!$userRoleToEdit) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para editar este usuario. Solo puedes editar usuarios que tú creaste.',
                    'timestamp' => now(),
                ], 403);
            }

            $authenticatedUserRole = UserRole::where('userId', $authenticatedUser->id)->first();

            $userToEdit->update([
                'email' => $request->email,
                'phone' => $request->phone,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Usuario actualizado exitosamente',
                'data' => [
                    'updated_user' => [
                        'id' => $userToEdit->id,
                        'firstName' => $userToEdit->firstName,
                        'lastName' => $userToEdit->lastName,
                        'email' => $userToEdit->email,
                        'phone' => $userToEdit->phone,
                        'profilePhoto' => $userToEdit->profilePhoto,
                        'status' => $userToEdit->status,
                    ],
                    'user_role_info' => [
                        'id' => $userRoleToEdit->id,
                        'roleId' => $userRoleToEdit->roleId,
                        'status' => $userRoleToEdit->status,
                        'createdBy' => $userRoleToEdit->createdBy
                    ],
                    'updated_by' => [
                        'id' => $authenticatedUser->id,
                        'name' => $authenticatedUser->firstName . ' ' . $authenticatedUser->lastName,
                        'email' => $authenticatedUser->email,
                        'role' => $authenticatedUserRole ? $authenticatedUserRole->roleId : null
                    ]
                ],
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al actualizar usuario: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function delete($id)
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();
            
            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $userToDelete = User::find($id);
            
            if (!$userToDelete) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $userRoleToDelete = UserRole::where('userId', $id)
                ->where('createdBy', $authenticatedUser->id)
                ->first();

            if (!$userRoleToDelete) {
                return response()->json([
                    'success' => false,
                    'message' => 'No tienes permisos para eliminar este usuario. Solo puedes eliminar usuarios que tú creaste.',
                    'timestamp' => now(),
                ], 403);
            }

            $schoolUser = SchoolUsers::where('userRoleId', $userRoleToDelete->id)->first();
            $schoolInfo = null;
            if ($schoolUser) {
                $school = Schools::find($schoolUser->schoolId);
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

            if ($schoolUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'No se puede eliminar este usuario porque está asignado a una escuela.',
                    'school' => $schoolInfo,
                    'timestamp' => now(),
                ], 400);
            }

            if (!$userToDelete->status) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario ya está inactivo',
                    'timestamp' => now(),
                ], 400);
            }

            $authenticatedUserRole = UserRole::where('userId', $authenticatedUser->id)->first();

            $userToDelete->update([
                'status' => false,
            ]);

            UserRole::where('userId', $id)->update([
                'status' => false,
            ]);

            $roleType = $userRoleToDelete->role ? $userRoleToDelete->role->name : "Rol " . $userRoleToDelete->roleId;

            return response()->json([
                'success' => true,
                'message' => 'Usuario eliminado (inactivado) exitosamente',
                'data' => [
                    'deleted_user' => [
                        'id' => $userToDelete->id,
                        'firstName' => $userToDelete->firstName,
                        'lastName' => $userToDelete->lastName,
                        'email' => $userToDelete->email,
                        'phone' => $userToDelete->phone,
                        'profilePhoto' => $userToDelete->profilePhoto,
                        'status' => $userToDelete->status,
                        'role_type' => $roleType
                    ],
                    'school' => $schoolInfo 
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al eliminar usuario: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function refreshToken()
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());
            
            $user = JWTAuth::setToken($newToken)->toUser();
            
            $userRole = UserRole::where('userId', $user->id)->first();
            
            return response()->json([
                'success' => true,
                'message' => 'Token renovado exitosamente',
                'data' => [
                    'token' => $newToken,
                    'user' => [
                        'id' => $user->id,
                        'firstName' => $user->firstName,
                        'lastName' => $user->lastName,
                        'role' => $userRole ? $userRole->roleId : null
                    ]
                ],
                'timestamp' => now(),
            ], 200);

        } catch (TokenExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token expirado y no se puede renovar. Inicia sesión nuevamente.',
                'error_code' => 'TOKEN_EXPIRED',
                'timestamp' => now(),
            ], 401);
        } catch (TokenInvalidException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token inválido',
                'error_code' => 'TOKEN_INVALID',
                'timestamp' => now(),
            ], 401);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'message' => 'No se pudo renovar el token',
                'error_code' => 'TOKEN_REFRESH_FAILED',
                'timestamp' => now(),
            ], 500);
        }
    }

    public function newPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:8',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'La nueva contraseña es obligatoria y debe tener mínimo 8 caracteres.',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado en el token',
                    'timestamp' => now(),
                ], 401);
            }

            $user->update([
                'password' => Hash::make($request->password)
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Contraseña actualizada exitosamente',
                'data' => [
                    'user_id' => $user->id,
                    'email' => $user->email,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al cambiar contraseña: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }
    // public function revive($id) algo para poder revivir un usuario eliminado quizá?
}
