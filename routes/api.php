<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Auth\RegisterController;
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
//
// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::group([

   'middleware' => ['api', 'auth:api'],
   'prefix' => 'auth'

], function ($router) {

    Route::match(['get','post'],'login', [AuthController::class,'login'])->withoutMiddleware(['auth:api']);
    Route::post('logout', [AuthController::class,'logout']);
    Route::match(['get','post'],'register', [RegisterController::class,'register'])->withoutMiddleware(['auth:api']);
    Route::post('refresh', [AuthController::class,'refresh'])->withoutMiddleware(['auth:api']);
    Route::get('user', [AuthController::class,'user']);

});
