<?php

namespace App\Http\Controllers;

use App\Models\AttendanceInfo;
use App\Models\AuthorizedPeople;
use App\Models\Guardians;
use App\Models\GuardiansSchool;
use App\Models\NotificationTemplates;
use App\Models\SentNotifications;
use App\Models\StudentAuthorized;
use App\Models\StudentGuardian;
use App\Models\Students;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;

class NotificationController extends Controller
{
    public function checkIn(Request $request)
    { 
        // Validar datos recibidos
        $request->validate([
            'archivo' => 'required|string',
            'tipo' => 'required|string|in:STUDENT',
        ]);

        // Buscar estudiante por el campo photo
        $student = Students::where('photo', $request->archivo)->first();

        if (!$student) {
            return response()->json([
                'success' => false,
                'message' => 'No se encontró ningún estudiante con esa foto.',
            ], 404);
        }

        // Crear registro en attendance_info
        $attendance = AttendanceInfo::create([
            'studentId' => $student->id,
            'checkIn' => now(),
            'checkOut' => null,
            'updatedAt' => null,
            'pickedUpById' => null,
            'pickedUpByType' => null,
        ]);

        // Buscar template de notificación tipo ENTRADA
        $template = NotificationTemplates::where('type', 'ENTRADA')->first();

        // Generar el mensaje personalizado
        $nombreEstudiante = $student->firstName . ' ' . $student->lastName;
        $mensaje = $template
            ? str_replace('[nombreEstudiante]', $nombreEstudiante, $template->message)
            : null;

        // Buscar los guardianes del estudiante
        $studentGuardians = StudentGuardian::where('studentId', $student->id)->get();

        $guardian1Id = $studentGuardians->get(0)?->guardianId;
        $guardian2Id = $studentGuardians->get(1)?->guardianId ?? null;

        // Crear registro en sent_notifications
        SentNotifications::create([
            'guardian1Id' => $guardian1Id,
            'guardian2Id' => $guardian2Id,
            'studentId' => $student->id,
            'attendanceInfoId' => $attendance->id,
            'message' => $mensaje,
            'type' => 'ENTRADA',
            'templateId' => $template ? $template->id : null,
            'sentAt' => now(),
            'status' => 'sent',
            'created_at' => now(),
        ]);

        return response()->json([
            'success' => true,
            'message' => 'Coincidencia encontrada en STUDENTS',
            'data' => [
                'archivo' => $request->archivo,
                'porcentaje_similitud' => $request->porcentaje_similitud,
                'tipo' => $request->tipo,
                'mensaje' => $mensaje,
            ]
        ]);
    }

    // se checa el tutor o a authorized, en el escritorio se recibe al padre o authorized (osea su id) para identificar, luego se le muestran los estudiantes, se escanean y se muestran, si sí son, se pueden clickear para confirmar los que ya llegaron (osea se envían los ids de los niños pero hasta no dar al checkbox de ellos, no se agregan a la petición, por lo que cuando ya se salen los niños, busca a los tutores para enviarles notificación como en checkIn, fin de la salida)
    public function checkOut(Request $request)
    {
        $request->validate([
            'personId' => 'required|integer',
            'personType' => 'required|string|in:GUARDIAN,AUTHORIZED',
            'studentIds' => 'required|array|min:1',
            'studentIds.*' => 'required|integer|distinct',
        ]);

        $personId = $request->personId;
        $personType = $request->personType;

        $students = [];

        if ($personType === 'GUARDIAN') {
            $studentGuardianRelations = StudentGuardian::where('guardianId', $personId)->get();

            // Por cada relación, busca el estudiante
            foreach ($studentGuardianRelations as $relation) {
                $student = Students::find($relation->studentId);
                if ($student) {
                    $students[] = $student;
                }
            }
        } else {
            $studentAuthorizedRelations = StudentAuthorized::where('authorizedPeopleId', $personId)->get();

            foreach ($studentAuthorizedRelations as $relation) {
                $student = Students::find($relation->studentId);
                if ($student) {
                    $students[] = $student;
                }
            }
        }

        $relatedStudentIds = collect($students)->pluck('id')->toArray();

        $requestedStudentIds = $request->studentIds;

        foreach ($requestedStudentIds as $id) {
            if (!in_array($id, $relatedStudentIds)) {
                return response()->json([
                    'success' => false,
                    'message' => 'Uno o más estudiantes no están relacionados con la persona.',
                    'invalidStudentId' => $id,
                    'timestamp' => now(),
                ], 400);
            }
        }

        foreach ($requestedStudentIds as $studentId) {
            // Buscar el último registro de asistencia del estudiante
            $attendance = AttendanceInfo::where('studentId', $studentId)
                ->orderByDesc('checkIn')
                ->first();

            if ($attendance) {
                $attendance->update([
                    'checkOut' => now(),
                    'updatedAt' => now(),
                    'pickedUpById' => $personId,
                    'pickedUpByType' => $personType,
                ]);
            }
        }

        foreach ($requestedStudentIds as $studentId) {
            $attendance = AttendanceInfo::where('studentId', $studentId)
                ->orderByDesc('checkIn')
                ->first();

            if ($attendance) {
                $attendance->update([
                    'checkOut' => now(),
                    'updatedAt' => now(),
                    'pickedUpById' => $personId,
                    'pickedUpByType' => $personType,
                ]);
            }
        }

        $guardianIds = GuardiansSchool::whereIn('student_id', $requestedStudentIds)
            ->pluck('guardian_id')
            ->unique()
            ->toArray();

        $guardians = Guardians::whereIn('id', $guardianIds)->get();

        // Buscar el template de notificación tipo SALIDA
        $template = NotificationTemplates::where('type', 'SALIDA')->first();

        // Obtener el nombre del responsable
        if ($personType === 'GUARDIAN') {
            $responsable = Guardians::find($personId);
            $nombreResponsable = $responsable ? ($responsable->firstName . ' ' . $responsable->lastName) : '';
        } else {
            $responsable = AuthorizedPeople::find($personId);
            $nombreResponsable = $responsable ? ($responsable->firstName . ' ' . $responsable->lastName) : '';
        }

        // Generar los mensajes para cada estudiante
        $mensajes = [];
        foreach ($requestedStudentIds as $studentId) {
            $student = Students::find($studentId);
            if ($student && $template) {
                $nombreEstudiante = $student->firstName . ' ' . $student->lastName;
                $mensaje = str_replace(
                    ['[nombreEstudiante]', '[nombreResponsable]'],
                    [$nombreEstudiante, $nombreResponsable],
                    $template->message
                );
                $mensajes[] = [
                    'studentId' => $studentId,
                    'mensaje' => $mensaje,
                ];
            }
        }

        foreach ($mensajes as $msg) {
            $studentId = $msg['studentId'];
            $mensaje = $msg['mensaje'];

            // Buscar el último registro de sent_notifications para ese estudiante, del mismo día
            $sentNotification = SentNotifications::where('studentId', $studentId)
                ->whereDate('created_at', Carbon::today())
                ->orderByDesc('created_at')
                ->first();

            if ($sentNotification) {
                $sentNotification->update([
                    'updated_at' => now(),
                    'last_type' => 'SALIDA',
                    'last_message' => $mensaje,
                ]);
            }
        }

        return response()->json([
            'success' => true,
            'message' => 'Salida registrada correctamente',
            'data' => [
                'personId' => $personId,
                'personType' => $personType,
                'students' => $students,
            ],
            'timestamp' => now(),
        ]);
    }

    public function sendNotification()
    {
        // igual y usamos fcm para poder generar las notificaciones sms, hacemos que cada que se haga checkin o checkout se busque el fcm_token de los guardianes y los otros monos y se envíe un mensaje genérico que diga TIENES NOTIFICACIONES NUEVAS, PRESIONA PARA VER y ya nomás que con eso entre en la vista de notificaciones, me falta una tabla de ver notificaciones
        // si es con fcm debo modificar la bd de guardians y de los authorized para meterles fcm_token y poder enviar la notificación
    }

    // este ya muestra todos, ahora lo que sigue es que separe las entradas de salidas, que tome el token del guardian para ubicar al guardian, que solo tenga a sus chiquillos al alcance de los filtros y ya
    // tengo un método que me devuelve solo a mis chiquillos según el guardian? porque lo ocupo aquí, estudiantes según el guardian
    public function myNotifications($studentId = null, $dayFilter = 4)
    {
        // Obtener el id del guardian desde el token, sin importar el modelo
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

        // Buscar todos los studentIds relacionados con este tutor
        $studentIds = StudentGuardian::where('guardianId', $guardian->id)
            ->pluck('studentId')
            ->toArray();

        if (empty($studentIds)) {
            return response()->json([
                'success' => true,
                'message' => 'No hay estudiantes asociados a este tutor',
                'data' => [],
                'count' => 0,
                'timestamp' => now(),
            ], 200);
        }

        $query = SentNotifications::query();

        // Filtrar por los studentIds del tutor
        $query->whereIn('studentId', $studentIds);

        // Si se envía un studentId específico, filtra solo ese
        if ($studentId && $studentId !== 'All') {
            $query->where('studentId', $studentId);
        }

        // Filtrar por fecha según dayFilter
        switch ((int)$dayFilter) {
            case 1: // Hoy
                $query->whereDate('created_at', Carbon::today());
                break;
            case 2: // Esta semana
                $query->whereBetween('created_at', [
                    Carbon::now()->startOfWeek(),
                    Carbon::now()->endOfWeek()
                ]);
                break;
            case 3: // Este mes
                $query->whereMonth('created_at', Carbon::now()->month)
                    ->whereYear('created_at', Carbon::now()->year);
                break;
            case 4: // Todos
            default:
                // Sin filtro extra
                break;
        }

        $notifications = $query->orderByDesc('created_at')->get();

        return response()->json([
            'success' => true,
            'data' => $notifications,
            'count' => $notifications->count(),
            'timestamp' => now(),
        ]);
    }

    public function signalSalida()
    {
        try {
            // Obtener el valor actual del cache (default: false)
            $currentMode = cache('student_mode', false);
            
            // Cambiar al valor contrario
            $newMode = !$currentMode;
            
            // Guardar el nuevo valor en cache (persiste indefinidamente)
            cache(['student_mode' => $newMode], now()->addYears(10));
            
            
            return response()->json([
                'success' => true,
                'message' => 'Modo estudiante cambiado exitosamente',
                'data' => [
                    'student_mode' => $newMode,
                    'previous_mode' => $currentMode,
                    'changed_at' => now()
                ],
                'timestamp' => now(),
            ], 200);
            
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al cambiar modo estudiante: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }

    public function studentMode()
    {
        try {
            // Obtener el valor actual del cache (default: false)
            $currentMode = cache('student_mode', false);
            
            // Cambiar al valor contrario
            $newMode = !$currentMode;
            
            // Guardar el nuevo valor en cache (persiste indefinidamente)
            cache(['student_mode' => $newMode], now()->addYears(10));
            
            
            return response()->json([
                'success' => true,
                'message' => 'Modo estudiante cambiado exitosamente',
                'data' => [
                    'student_mode' => $newMode,
                    'previous_mode' => $currentMode,
                    'changed_at' => now()
                ],
                'timestamp' => now(),
            ], 200);
            
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Error al cambiar modo estudiante: ' . $e->getMessage(),
                'timestamp' => now(),
            ], 500);
        }
    }
}
