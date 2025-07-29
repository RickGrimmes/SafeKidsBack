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

    Route::get('debugToken', [GuardianController::class, 'debugToken']);
    
    // USERS
    Route::post('users/login', [UserController::class, 'login']);
    Route::post('users/reset-password', [UserController::class, 'resetPassword']);
    Route::post('users/verify-2fa', [UserController::class, 'verify2FA']);
    Route::post('users/password-challenge', [UserController::class, 'passwordChallenge']);
    Route::post('users/change-password', [UserController::class, 'changePassword']);
    Route::post('users/refresh-token', [UserController::class, 'refreshToken']);
    Route::post('users/resend-2fa', [UserController::class, 'resend2FA']);

    // GUARDIANS
    Route::post('guardians/login', [GuardianController::class, 'login']);
    Route::post('guardians/reset-password', [GuardianController::class, 'resetPassword']);
    Route::post('guardians/verify-2fa', [GuardianController::class, 'verify2FA']);
    // EL VERIFY2FA TE DEVUELVE AL USUARIO CON SU TOKEN Y LOS DATOS DE LA ESCUELA EN LA QUE ESTÁ ASOCIADO, EL OBJETO SE LLAMA SCHOOL, SALDRÁ NULL SI NO ESTÁ ENLAZADO A ALGUNA ESCUELA POR LO QUE SI TE SALE NULL, PRIMERO CHECA QUE ESTE TENGA UNA RELACIÓN A ALGUNA ESCUELA EXISTENTE
    Route::post('guardians/refresh-token', [GuardianController::class, 'refreshToken']);

    Route::middleware('jwt.auth')->group(function () 
    {
        // USERS
        Route::post('users/register', [UserController::class, 'register']);
        Route::get('users/type/{type}', [UserController::class, 'index']); 
        Route::post('users/logout', [UserController::class, 'logout']);
        Route::get('users/my-directors', [UserController::class, 'myDirectors']);
        Route::get('users/my-profile', [UserController::class, 'myProfile']);
        Route::put('users/edit/{id}', [UserController::class, 'edit']);
        Route::delete('users/delete/{id}', [UserController::class, 'delete']);
        Route::post('users/new-password', [UserController::class, 'newPassword']);

        // SCHOOLS
        Route::get('schools', [SchoolController::class, 'index']);
        Route::get('schools/{id}', [SchoolController::class, 'show']);
        Route::post('schools/create', [SchoolController::class, 'create']);
        Route::put('schools/edit/{id}', [SchoolController::class, 'edit']);
        Route::delete('schools/delete/{id}', [SchoolController::class, 'delete']);

        // STUDENTS
        Route::get('students/{id}', [StudentController::class, 'show']);
        Route::get('students/seek-school/{schoolId}/{filter}', [StudentController::class, 'index']);
        Route::put('students/edit-group/{studentId}', [StudentController::class, 'editGroup']);
        Route::delete('students/delete/{id}', [StudentController::class, 'delete']);
        Route::post('students/create/{schoolId}', [StudentController::class, 'create']);

        //GROUPS
        Route::get('groups/{schoolId}', [GroupController::class, 'index']);

        // AUTHORIZEDPEOPLES
        Route::post('authPeoples/{studentId}', [AuthorizedPeopleController::class, 'create']);
        Route::get('authPeoples/{id}', [AuthorizedPeopleController::class, 'show']);
        Route::put('authPeoples/{id}', [AuthorizedPeopleController::class, 'edit']);
        Route::delete('authPeoples/{id}', [AuthorizedPeopleController::class, 'delete']);
        Route::get('authPeoples/my-authorizeds/{studentId}', [AuthorizedPeopleController::class, 'myAuthorizeds']);
        Route::get('authPeoples/students/{schoolId}', [AuthorizedPeopleController::class, 'index']);

        // GUARDIANS
        Route::get('guardians/my-profile', [GuardianController::class, 'myProfile']);
        Route::post('guardians/register/{schoolId}', [GuardianController::class, 'register']);
        Route::post('guardians/logout', [GuardianController::class, 'logout']);
        Route::get('guardians/{id}', [GuardianController::class, 'show']);
        Route::get('guardians/{schoolId}/{studentId}', [GuardianController::class, 'index']);
        Route::put('guardians/edit/{id}', [GuardianController::class, 'edit']);
        Route::delete('guardians/delete/{id}', [GuardianController::class, 'delete']);
        Route::post('guardians/new-password', [GuardianController::class, 'newPassword']);
        //Route::get('guardians/my-guardians', [GuardianController::class, 'myGuardians']); ESTA CREO QUE NO
        Route::get('guardians/all/{studentId}', [GuardianController::class, 'guardiansList']); 
        Route::get('guardians/my-kids', [GuardianController::class, 'myKids']); //para obtener a los hijos del tutor

        // TODO LO DE LA CÁMARA SKRAAAAAAAAA
    });
    
    
    // NOTIFICACIONES
    Route::prefix('entrada')->group(function () {
        Route::get('create', [NotificationController::class, 'create']);
    });

    Route::prefix('salida')->group(function () {
        Route::get('prueba', [NotificationController::class, 'prueba']);
    });
});
