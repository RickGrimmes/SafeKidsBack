<?php

namespace App\Http\Controllers;

use App\Mail\ResetPasswordMail;
use App\Mail\TwoFactorAuthMail;
use App\Models\Groups;
use App\Models\Guardians;
use App\Models\GuardiansSchool;
use App\Models\StudentGuardian;
use App\Models\Students;
use App\Models\User;
use App\Models\UserRole;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Facades\JWTAuth;

class GuardianController extends Controller
{
    public function register(Request $request, $schoolId)
    {
        try
        {
            $validator = Validator::make($request->all(), [
                'firstName' => 'required|string|max:50',
                'lastName' => 'required|string|max:50',
                'phone' => 'required|string|max:10',
                'email' => 'required|email|unique:guardians,email',
                'photo' => 'required|image|mimes:jpg,jpeg,png|max:2048',
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
            $creatorRole = UserRole::where('userId', $creatorId)->first();

            if (!$creatorRole) {
                return response()->json([
                    'success' => false,
                    'message' => 'El usuario creador no tiene un rol asignado.',
                    'timestamp' => now(),
                ], 400);
            }

            if ($creatorRole->roleId != 4) {
                return response()->json([
                    'success' => false,
                    'message' => 'El rol del usuario creador no es válido.',
                    'timestamp' => now(),
                ], 400);
            }

            $guardian = Guardians::create([
                'firstName' => $request->firstName,
                'lastName' => $request->lastName,
                'phone' => $request->phone,
                'email' => $request->email,
                'photo' => '',
                'password' => Hash::make($request->password),
                'status' => true,
            ]);

            if ($request->hasFile('photo')) {
                $file = $request->file('photo');
                $firstName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $guardian->firstName));
                $lastName = strtoupper(iconv('UTF-8', 'ASCII//TRANSLIT', $guardian->lastName));
                $fullName = preg_replace('/\s+/', '', $firstName . $lastName);
                $fileName = $guardian->id . '_' . $fullName . '.jpg';
                $guardian->photo = $fileName;
                $guardian->save();
            }

            GuardiansSchool::create([
                'guardian_id' => $guardian->id,
                'school_id' => $schoolId,
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Tutor registrado correctamente',
                'data' => $guardian,
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
                    'message' => 'Validación fallida',
                    'timestamp' => now(),
                ], 400);
            }

            $guardians = Guardians::where('email', $request->email)->first();

            if ($guardians && Hash::check($request->password, $guardians->password))
            {
                if (!$guardians->status) {
                    return response()->json([
                        'success' => false,
                        'message' => 'El tutor está inactivo',
                        'timestamp' => now(),
                    ], 403);
                }

                $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            
                $guardians->update(['2facode' => $code]);

                $temporaryToken = base64_encode(json_encode([
                    'email' => $guardians->email,
                    'expires_at' => now()->addMinutes(15)->timestamp,
                    'type' => 'guardian' 
                ]));
                
                Mail::to($guardians->email)->send(new TwoFactorAuthMail($guardians, $code));

                return response()->json([
                    'success' => true,
                    'message' => 'Login exitoso',
                    'data' => $guardians,
                    'temporaryToken' => $temporaryToken,
                    'timestamp' => now(),
                ], 200);
            }
            else
            {
                return response()->json([
                    'success' => false,
                    'message' => 'Credenciales inválidas',
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
                    'message' => 'El email es obligatorio y debe ser válido',
                    'timestamp' => now(),
                ], 400);
            }

            $guardian = Guardians::where('email', $request->email)->first();

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            $guardian->update(['2facode' => $code]);

            Mail::to($guardian->email)->send(new ResetPasswordMail($guardian, $code));

            return response()->json([
                'success' => true,
                'message' => 'Email de restablecimiento de contraseña enviado',
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
        try {
            $validator = Validator::make($request->all(), [
                'temporaryToken' => 'required|string',
                'code' => 'required|string|size:6',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Validación fallida, se requiere un token temporal y un código de 6 dígitos',
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

            $guardian = Guardians::where('email', $tokenData['email'])->first();

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            if ($guardian->{'2facode'} !== $request->code) {
                return response()->json([
                    'success' => false,
                    'message' => 'Código 2FA inválido',
                    'timestamp' => now(),
                ], 400);
            }

            if (!$guardian instanceof Guardians) {
                return response()->json([
                    'success' => false,
                    'message' => 'No es un tutor válido',
                    'timestamp' => now(),
                ], 403);
            }

            try {
                $token = JWTAuth::fromUser($guardian);
            } catch (\Exception $e) {
                return response()->json([
                    'success' => false,
                    'message' => 'Error al generar el token para tutor: ' . $e->getMessage(),
                    'timestamp' => now(),
                ], 500);
            }

            $studentIds = StudentGuardian::where('guardianId', $guardian->id)
                ->pluck('studentId')
                ->toArray();

            $students = Students::whereIn('id', $studentIds)
                ->where('status', true)
                ->get();

            $guardian->update(['2facode' => null]);

            return response()->json([
                'success' => true,
                'message' => 'Login completado con éxito',
                'data' => $guardian->makeHidden(['password', '2facode', 'created_at']),
                'token' => $token,
                'students' => $students,
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

        $guardian = Guardians::where('2facode', $request->code)->first();

        if (!$guardian) {
            return response()->json([
                'success' => false,
                'message' => 'Código inválido o expirado',
                'timestamp' => now(),
            ], 400);
        }

        $resetToken = base64_encode(json_encode([
            'guardian_id' => $guardian->id,
            'email' => $guardian->email,
            'purpose' => 'password_reset',
            'expires_at' => now()->addMinutes(15)->timestamp,
            'verification_code' => $request->code
        ]));

        return response()->json([
            'success' => true,
            'message' => 'Código verificado correctamente',
            'data' => [
                'guardian_id' => $guardian->id,
                'email' => $guardian->email,
                'firstName' => $guardian->firstName,
                'lastName' => $guardian->lastName
            ],
            'resetToken' => $resetToken,
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
                'password_confirmation' => 'required|string|min:8',
            ]);

            if ($validator->fails()) {
                $errors = $validator->errors();
                if ($errors->has('password')) {
                    $msg = 'La nueva contraseña es obligatoria y debe tener mínimo 8 caracteres.';
                } elseif ($errors->has('password_confirmation')) {
                    $msg = 'La confirmación de contraseña es obligatoria y debe tener mínimo 8 caracteres.';
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

            if ($request->password !== $request->password_confirmation) {
                return response()->json([
                    'success' => false,
                    'message' => 'Las contraseñas no coinciden.',
                    'timestamp' => now(),
                ], 400);
            }

            // Decodificar y validar el token temporal
            $tokenData = json_decode(base64_decode($request->resetToken), true);

            if (!$tokenData || !isset($tokenData['guardian_id'], $tokenData['expires_at'], $tokenData['purpose'])) {
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
            $guardian = Guardians::find($tokenData['guardian_id']);

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            // Validar que el código de verificación aún coincida (seguridad extra)
            if (isset($tokenData['verification_code']) && $guardian->{'2facode'} !== $tokenData['verification_code']) {
                return response()->json([
                    'success' => false,
                    'message' => 'Token de reset inválido o ya utilizado',
                    'timestamp' => now(),
                ], 400);
            }

            // Actualizar la contraseña y limpiar el código 2FA
            $guardian->update([
                'password' => Hash::make($request->password),
                '2facode' => null 
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Contraseña actualizada exitosamente',
                'data' => [
                    'guardian_id' => $guardian->id,
                    'email' => $guardian->email,
                    'firstName' => $guardian->firstName,
                    'lastName' => $guardian->lastName,
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

    public function resend2fa(Request $request)  
    {
        try {
            $validator = Validator::make($request->all(), [
                'temporaryToken' => 'required|string',
            ]);
            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'El token temporal es obligatorio',
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
            $guardian = Guardians::where('email', $tokenData['email'])->first();
            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no encontrado',
                    'timestamp' => now(),
                ], 404);
            }
            $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $guardian->update(['2facode' => $code]);
            Mail::to($guardian->email)->send(new TwoFactorAuthMail($guardian, $code));
            return response()->json([
                'success' => true,
                'message' => 'Código de 2FA reenviado con éxito',
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
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
                'message' => 'Logout exitoso',
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Logout fallido',
                'timestamp' => now(),
            ], 500);
        }
    }

    public function show($id) //PARA QUE LO VEA EN ESCRITORIO
    {
        try {
            $authenticatedUser = JWTAuth::parseToken()->authenticate();

            if (!$authenticatedUser) {
                return response()->json([
                    'success' => false,
                    'message' => 'Usuario no autenticado',
                    'timestamp' => now(),
                ], 401);
            }

            $guardian = Guardians::find($id);

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $data = $guardian->makeHidden(['2facode', 'password', 'created_at']);

            return response()->json([
                'success' => true,
                'message' => 'Tutor encontrado exitosamente',
                'data' => $data,
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Server failed',
                'timestamp' => now(),
            ], 500);
        }
    }

    public function myProfile() //PARA QUE LO VEA EN MÓVIL
    {
        try {
            $tokenPayload = null;
            try {
                $tokenPayload = JWTAuth::parseToken()->getPayload()->toArray();
            } catch (\Exception $e) {
                $tokenPayload = null;
            }

            $id = $tokenPayload['sub'] ?? null;
            $guardian = $id ? Guardians::find($id) : null;

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'token_id' => $id,
                    'timestamp' => now(),
                ], 404);
            }

            $data = $guardian->makeHidden(['2facode', 'password', 'created_at']);

            return response()->json([
                'success' => true,
                'message' => 'Perfil del tutor recuperado exitosamente',
                'data' => $data,
                'token_id' => $id,
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            $tokenPayload = null;
            $id = null;
            try {
                $tokenPayload = JWTAuth::parseToken()->getPayload()->toArray();
                $id = $tokenPayload['sub'] ?? null;
            } catch (\Exception $ex) {
                $id = null;
            }
            return response()->json([
                'success' => false,
                'message' => 'Server failed',
                'token_id' => $id,
                'timestamp' => now(),
            ], 500);
        }
    }
    
    public function index($schoolId, $studentId = 'ALL')
    {
        try {
            $guardianIds = GuardiansSchool::where('school_id', $schoolId)
                ->pluck('guardian_id')
                ->toArray();

            if (strtoupper($studentId) === 'ALL') {
                $guardians = Guardians::whereIn('id', $guardianIds)
                    ->where('status', true)
                    ->get();

                $studentIds = Groups::where('schoolId', $schoolId)
                    ->pluck('studentId')
                    ->unique()
                    ->toArray();

                $students = Students::whereIn('id', $studentIds)
                    ->where('status', true)
                    ->get()
                    ->map(function ($student) {
                        return $student->firstName . ' ' . $student->lastName;
                    });

                return response()->json([
                    'success' => true,
                    'message' => 'Guardians y estudiantes de la escuela encontrados exitosamente',
                    'students' => $students,
                    'data' => $guardians->makeHidden(['password', '2facode', 'created_at']),
                    'timestamp' => now(),
                ], 200);
            }

            if (is_numeric($studentId)) {
                $studentGuardianIds = StudentGuardian::where('studentId', $studentId)
                    ->whereIn('guardianId', $guardianIds)
                    ->pluck('guardianId')
                    ->toArray();

                $guardians = Guardians::whereIn('id', $studentGuardianIds)
                    ->where('status', true)
                    ->get();

                $student = Students::find($studentId);
                $studentName = $student ? $student->firstName . ' ' . $student->lastName : null;

                return response()->json([
                    'success' => true,
                    'message' => 'Guardians y estudiante encontrados exitosamente',
                    'students' => $studentName ? [$studentName] : [],
                    'data' => $guardians->makeHidden(['password', '2facode', 'created_at']),
                    'timestamp' => now(),
                ], 200);
            }

            return response()->json([
                'success' => false,
                'message' => 'Parámetro inválido',
                'timestamp' => now(),
            ], 400);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar tutores: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function edit(Request $request, $id)
    {
        try {
            $validator = Validator::make($request->all(), [
                'phone' => 'sometimes|required|string|max:10',
                'email' => 'sometimes|required|email',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Datos inválidos para editar tutor',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            $guardian = Guardians::findOrFail($id);

            if ($request->has('email')) {
                $emailExists = Guardians::where('email', $request->email)
                    ->where('id', '!=', $guardian->id)
                    ->exists();

                if ($emailExists) {
                    return response()->json([
                        'success' => false,
                        'message' => 'El correo ya está registrado por otro usuario.',
                        'timestamp' => now(),
                    ], 400);
                }
                $guardian->email = $request->email;
            }

            if ($request->has('phone')) {
                $guardian->phone = $request->phone;
            }

            $guardian->save();

            return response()->json([
                'success' => true,
                'message' => 'Tutor actualizado correctamente',
                'data' => $guardian->makeHidden(['password', '2facode', 'created_at']),
                'timestamp' => now(),
            ], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Tutor no encontrado',
                'timestamp' => now(),
            ], 404);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al editar tutor: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function delete($id)
    {
        try {
            $guardian = Guardians::findOrFail($id);

            $guardian->update(['status' => false]);

            return response()->json([
                'success' => true,
                'message' => 'Tutor dado de baja correctamente',
                'data' => [
                    'guardian_id' => $guardian->id,
                    'status' => $guardian->status,
                ],
                'timestamp' => now(),
            ], 200);

        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Tutor no encontrado',
                'timestamp' => now(),
            ], 404);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al dar de baja tutor: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function newPassword(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'password' => 'required|string|min:8',
                'password_confirmation' => 'required|string|min:8',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'La nueva contraseña y su confirmación son obligatorias y deben tener mínimo 8 caracteres.',
                    'errors' => $validator->errors(),
                    'timestamp' => now(),
                ], 400);
            }

            if ($request->password !== $request->password_confirmation) {
                return response()->json([
                    'success' => false,
                    'message' => 'Las contraseñas no coinciden.',
                    'timestamp' => now(),
                ], 400);
            }

            $userFromToken = JWTAuth::parseToken()->authenticate();

            if (!$userFromToken) {
                return response()->json([
                    'success' => false,
                    'message' => 'No se pudo autenticar el usuario del token.',
                    'timestamp' => now(),
                ], 403);
            }

            $guardian = Guardians::find($userFromToken->id);

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'No se encontró el tutor para cambiar la contraseña.',
                    'timestamp' => now(),
                ], 404);
            }

            $guardian->update([
                'password' => Hash::make($request->password)
            ]);

            return response()->json([
                'success' => true,
                'message' => 'Contraseña actualizada exitosamente',
                'data' => [
                    'guardian_id' => $guardian->id,
                    'email' => $guardian->email,
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

    public function myGuardiansOld() 
    {
        try {
            $guardian = JWTAuth::parseToken()->authenticate();

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            $guardians = Guardians::where('id', $guardian->id)->get();

            return response()->json([
                'success' => true,
                'message' => 'Tutores recuperados exitosamente',
                'data' => $guardians->makeHidden(['2facode', 'password', 'created_at']),
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Server failed',
                'timestamp' => now(),
            ], 500);
        }
    }

    public function myGuardians()
    {
        try {
            // Obtener el id del tutor desde el token, sin importar el modelo
            $tokenPayload = null;
            try {
                $tokenPayload = JWTAuth::parseToken()->getPayload()->toArray();
            } catch (\Exception $e) {
                $tokenPayload = null;
            }

            $id = $tokenPayload['sub'] ?? null;
            $guardian = $id ? Guardians::find($id) : null;

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'timestamp' => now(),
                ], 404);
            }

            // 1. Buscar el primer registro en student_guardian para este tutor
            $studentGuardian = StudentGuardian::where('guardianId', $guardian->id)->first();

            if (!$studentGuardian) {
                return response()->json([
                    'success' => true,
                    'message' => 'No hay estudiantes asociados a este tutor',
                    'data' => [],
                    'timestamp' => now(),
                ], 200);
            }

            $studentId = $studentGuardian->studentId;

            // 2. Buscar todos los guardianes asociados a ese estudiante
            $guardianIds = StudentGuardian::where('studentId', $studentId)
                ->pluck('guardianId')
                ->toArray();

            // 3. Omitir al tutor que inició la petición
            $guardianIds = array_filter($guardianIds, function($gid) use ($guardian) {
                return $gid != $guardian->id;
            });

            // 4. Obtener los datos de los guardianes restantes
            $guardians = Guardians::whereIn('id', $guardianIds)
                ->where('status', true)
                ->get();

            return response()->json([
                'success' => true,
                'message' => 'Tutores relacionados encontrados exitosamente',
                'data' => $guardians->makeHidden(['password', '2facode', 'created_at']),
                'timestamp' => now(),
            ], 200);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar tutores: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function guardiansList($studentId)
    {
        try {
            $guardianIds = StudentGuardian::where('studentId', $studentId)
                ->pluck('guardianId')
                ->toArray();

            $guardians = Guardians::whereIn('id', $guardianIds)
                ->where('status', true)
                ->get();

            return response()->json([
                'success' => true,
                'message' => 'Tutores relacionados encontrados exitosamente',
                'data' => $guardians->makeHidden(['password', '2facode', 'created_at']),
                'timestamp' => now(),
            ], 200);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al consultar tutores: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function myKids()
    {
        try {
            // Toma el token y saca el id
            $tokenPayload = JWTAuth::parseToken()->getPayload()->toArray();
            $id = $tokenPayload['sub'];

            // Busca en guardians por ese id
            $guardian = Guardians::find($id);

            if (!$guardian) {
                return response()->json([
                    'success' => false,
                    'message' => 'Tutor no encontrado',
                    'token_id' => $id,
                    'timestamp' => now(),
                ], 404);
            }

            // Busca los estudiantes asociados
            $studentIds = StudentGuardian::where('guardianId', $guardian->id)
                ->pluck('studentId')
                ->toArray();

            $students = Students::whereIn('id', $studentIds)
                ->where('status', true)
                ->get();

            return response()->json([
                'success' => true,
                'message' => 'Estudiantes asociados encontrados exitosamente',
                'data' => $students,
                'token_id' => $id,
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
    
    public function refreshToken()
    {
        try {
            $newToken = JWTAuth::refresh(JWTAuth::getToken());
            
            $user = JWTAuth::setToken($newToken)->authenticate();
            
            $role = null;
        if ($user instanceof User) {
            $userRole = UserRole::where('userId', $user->id)->first();
            $role = $userRole ? $userRole->roleId : null;
        }
            return response()->json([
                'success' => true,
                'message' => 'Token renovado exitosamente',
                'data' => [
                    'token' => $newToken,
                    'user' => [
                        'id' => $user->id,
                        'firstName' => $user->firstName,
                        'lastName' => $user->lastName,
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
}
