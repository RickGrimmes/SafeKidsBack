<?php

namespace App\Http\Controllers;

use App\Models\AttendanceInfo;
use App\Models\AuthorizedPeople;
use App\Models\Guardians;
use App\Models\NotificationTemplates;
use App\Models\SentNotifications;
use App\Models\StudentAuthorized;
use App\Models\StudentGuardian;
use App\Models\Students;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

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
    // ya toma al guardian o auth, ve a sus chiquillos, sigue que haga ya la notificación pero creo que hay que modificar la bd para tener guardado el mensaje o así
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
}
