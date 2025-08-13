<?php

use App\Http\Controllers\AuthorizedPeopleController;
use App\Http\Controllers\GroupController;
use App\Http\Controllers\GuardianController;
use App\Http\Controllers\NotificationController;
use App\Http\Controllers\SchoolController;
use App\Http\Controllers\StudentController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::prefix('api1')->group(function () {
    
    #region USERS
    Route::post('users/login', [UserController::class, 'login']);
    Route::post('users/reset-password', [UserController::class, 'resetPassword']);
    Route::post('users/verify-2fa', [UserController::class, 'verify2FA']);
    Route::post('users/password-challenge', [UserController::class, 'passwordChallenge']);
    Route::post('users/change-password', [UserController::class, 'changePassword']);
    Route::post('users/refresh-token', [UserController::class, 'refreshToken']);
    Route::post('users/resend-2fa', [UserController::class, 'resend2FA']);
    #endregion

    #region GUARDIANS
    Route::post('guardians/login', [GuardianController::class, 'login']);
    Route::post('guardians/reset-password', [GuardianController::class, 'resetPassword']); //si le da a olvidé contraseña, usa este, pide el correo para saber a quién enviar el código de restablecimiento
    Route::post('guardians/verify-2fa', [GuardianController::class, 'verify2FA']);
    Route::post('guardians/password-challenge', [GuardianController::class, 'passwordChallenge']); //sigue aquí para verificar la contraseña del usuario antes de cambiarla, le pido el código y si sí le doy el resetToken para que vaya a modificar
    Route::post('guardians/change-password', [GuardianController::class, 'changePassword']); //si todo bien, pasa por acá y pido el resetToken para saber a quién es, pido contraseña y listo
    // EL VERIFY2FA TE DEVUELVE AL USUARIO CON SU TOKEN Y LOS DATOS DE LA ESCUELA EN LA QUE ESTÁ ASOCIADO, EL OBJETO SE LLAMA SCHOOL, SALDRÁ NULL SI NO ESTÁ ENLAZADO A ALGUNA ESCUELA POR LO QUE SI TE SALE NULL, PRIMERO CHECA QUE ESTE TENGA UNA RELACIÓN A ALGUNA ESCUELA EXISTENTE
    Route::post('guardians/refresh-token', [GuardianController::class, 'refreshToken']);
    Route::post('guardians/resend-2fa', [GuardianController::class, 'resend2FA']); //viene del passwordChallenge, si le pongo que me reenvíe el 2fa, este pide el código que pusiste, para ubicar al tutor y ya con eso re enviarle el código
    
    #endregion

    Route::middleware('jwt.auth')->group(function () 
    {
        #region USERS
        Route::post('users/register', [UserController::class, 'register']); // para crear usuarios que no sean tipo dueño
        Route::post('users/register-owner', [UserController::class, 'registerOwner']); //para usuarios tipo dueño nada mas
        Route::post('users/logout', [UserController::class, 'logout']);
        Route::get('users/my-directors', [UserController::class, 'myDirectors']); // trae a los directores que he creado, que están en status 1 y que no tengan escuelas en las que ya estén metidos
        Route::get('users/my-profile', [UserController::class, 'myProfile']);
        Route::post('users/new-password', [UserController::class, 'newPassword']);
        Route::get('users/type/{type}', [UserController::class, 'index']); 
        Route::put('users/edit/{id}', [UserController::class, 'edit']);
        Route::delete('users/delete/{id}', [UserController::class, 'delete']);
        #endregion

        #region SCHOOLS
        Route::get('schools', [SchoolController::class, 'index']);
        Route::post('schools/create', [SchoolController::class, 'create']);
        Route::get('schools/my-schools', [SchoolController::class, 'mySchools']); // para que el usuario obtenga las escuelas que ha creado pero solo las que no tengan directores y su status es true, método auxiliar para crear director
        Route::put('schools/edit/{id}', [SchoolController::class, 'edit']);
        Route::delete('schools/delete/{id}', [SchoolController::class, 'delete']);
        Route::get('schools/{id}', [SchoolController::class, 'show']);
        #endregion

        #region STUDENTS
        Route::get('students/seek-school/{schoolId}/{filter}', [StudentController::class, 'index']);
        Route::put('students/edit-group/{studentId}', [StudentController::class, 'editGroup']); //también edita la foto del chiquillo
        Route::delete('students/delete/{id}', [StudentController::class, 'delete']);
        Route::post('students/create/{schoolId}', [StudentController::class, 'create']);
        Route::get('students/{id}', [StudentController::class, 'show']);
        #endregion

        #region GROUPS
        Route::get('groups/{schoolId}', [GroupController::class, 'index']);
        #endregion

        #region AUTHORIZEDPEOPLES
        Route::get('authPeoples/my-authorizeds/{studentId}', [AuthorizedPeopleController::class, 'myAuthorizeds']);
        Route::post('authPeoples/create', [AuthorizedPeopleController::class, 'create']);
        Route::get('authPeoples/show/{id}', [AuthorizedPeopleController::class, 'show']);
        Route::put('authPeoples/edit/{id}', [AuthorizedPeopleController::class, 'edit']);
        Route::delete('authPeoples/delete/{id}', [AuthorizedPeopleController::class, 'delete']);
        Route::get('authPeoples/{schoolId}/{studentId}', [AuthorizedPeopleController::class, 'index']);
        #endregion

        #region GUARDIANS
        Route::get('guardians/my-profile', [GuardianController::class, 'myProfile']);
        Route::get('guardians/my-guardians', [GuardianController::class, 'myGuardians']); // para ver a los demás tutores aparte de yo tutor, para vista móvil
        Route::get('guardians/my-kids', [GuardianController::class, 'myKids']); //para obtener a los hijos del tutor, sirve también para el filtro de mis hijos en notificaciones
        Route::post('guardians/register/{schoolId}', [GuardianController::class, 'register']);
        Route::post('guardians/logout', [GuardianController::class, 'logout']);
        Route::post('guardians/new-password', [GuardianController::class, 'newPassword']);
        Route::get('guardians/all/{studentId}', [GuardianController::class, 'guardiansList']);
        Route::get('guardians/{id}', [GuardianController::class, 'show']);
        Route::put('guardians/edit/{id}', [GuardianController::class, 'edit']);
        Route::delete('guardians/delete/{id}', [GuardianController::class, 'delete']);
        Route::get('guardians/{schoolId}/{studentId}', [GuardianController::class, 'index']);
        #endregion

        #region NOTIFICATIONS
        Route::get('notifications/my-notifications/{studentId}/{dayFilter}', [NotificationController::class, 'myNotifications']);
        Route::get('notifications/check-notifications', [NotificationController::class, 'checkForNewNotifications']);
       
        #endregion
        
        // PARA LA CÁMARA
        // PARA GUARDAR LAS IMÁGENES DEBE DE USAR TANTO LOS MÉTODOS DE CREAR Y REGISTRAR DE AQUÍ, COMO LOS DE PYTHON, LARAVEL SOLO CAPTURA LOS DATOS Y PYTHON LA IMAGEN PARA GUARDARLA EN EL DISCO
    });
    
    #region NOTIFICACIONES SALIDA Y ENTRADA
    Route::prefix('entrada')->group(function () {
        Route::post('check-in', [NotificationController::class, 'checkIn']);
    });

    Route::prefix('salida')->group(function () {
        Route::get('check-out', [NotificationController::class, 'checkOut']);
    });

    #endregion

    #region SEÑAL SALIDA
    Route::post('salida/signal', [NotificationController::class, 'signalSalida']); // le dice a python que ahora se va a ir a buscar GUARDIANS o STUDENTS en la salida, pero probablemente no se use
    #endregion
});
