<?php

use App\Http\Controllers\GuardianController;
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
    //Route::get('users/type/{type}', [UserController::class, 'index']);

    // GUARDIANS
    Route::post('guardians/login', [GuardianController::class, 'login']);
    Route::post('guardians/reset-password', [GuardianController::class, 'resetPassword']);
    Route::post('guardians/verify-2fa', [GuardianController::class, 'verify2FA']);
    //Route::get('guardians/{id}', [GuardianController::class, 'show']);

    Route::middleware('jwt.auth')->group(function () 
    {
        Route::post('users/register', [UserController::class, 'register']);
        Route::get('users/type/{type}', [UserController::class, 'index']);
        Route::post('users/logout', [UserController::class, 'logout']);
        Route::post('guardians/register', [GuardianController::class, 'register']);
        Route::post('guardians/logout', [GuardianController::class, 'logout']);
        Route::get('guardians/{id}', [GuardianController::class, 'show']);
    });
    
});



