<?php

use App\Http\Controllers\GuardianController;
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

    // USERS
    Route::post('users/login', [UserController::class, 'login']);
    Route::post('users/reset-password', [UserController::class, 'resetPassword']);
    Route::post('users/verify-2fa', [UserController::class, 'verify2FA']);
    Route::post('users/password-challenge', [UserController::class, 'passwordChallenge']);
    Route::post('users/change-password', [UserController::class, 'changePassword']);

    // GUARDIANS
    Route::post('guardians/login', [GuardianController::class, 'login']);
    Route::post('guardians/reset-password', [GuardianController::class, 'resetPassword']);
    Route::post('guardians/verify-2fa', [GuardianController::class, 'verify2FA']);

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

        // GUARDIANS
        Route::post('guardians/register', [GuardianController::class, 'register']);
        Route::post('guardians/logout', [GuardianController::class, 'logout']);
        Route::get('guardians/{id}', [GuardianController::class, 'show']);
        //Route::get('guardians', [GuardianController::class, 'index']);
        //Route::get('guardians/all/{student}', [GuardianController::class, 'guardiansList']);
        //Route::put('guardians/edit/{id}', [GuardianController::class, 'edit']);
        //Route::delete('guardians/delete/{id}', [GuardianController::class, 'delete']);
        

        // AUTHORIZEDPEOPLES SIN HACER
        Route::get('authPeoples/{student}', [GuardianController::class, 'authPeopleByStudent']);
        Route::get('authPeoples/{id}', [GuardianController::class, 'show']);
        Route::post('authPeoples', [GuardianController::class, 'create']);
        Route::get('authPeoples/{id}', [GuardianController::class, 'index']);
        Route::put('authPeoples/{id}', [GuardianController::class, 'edit']);
        Route::delete('authPeoples/{id}', [GuardianController::class, 'delete']);

        // SCHOOLS
        Route::get('schools', [SchoolController::class, 'index']);
        Route::get('schools/{id}', [SchoolController::class, 'show']);
        Route::post('schools/create', [SchoolController::class, 'create']);
        //Route::put('schools/edit/{id}', [SchoolController::class, 'edit']);
        Route::delete('schools/delete/{id}', [SchoolController::class, 'delete']);

        // STUDENTS SIN HACER
        Route::post('students/create', [StudentController::class, 'create']);
        Route::get('students/{filter}', [StudentController::class, 'index']);
        Route::put('students/editGroup/{id}', [StudentController::class, 'editGroup']);
        Route::get('students/{id}', [StudentController::class, 'show']);
        Route::delete('students/delete/{id}', [StudentController::class, 'delete']);

        // TODO LO DE LA CÁMARA
    });
    
});



