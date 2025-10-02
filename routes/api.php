<?php

use App\Http\Controllers\ArticleController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
Route::get('/articles', [ArticleController::class, 'index']);
Route::post('/user/signup',[UserController::class,'register']);
Route::post('/user/signin',[UserController::class,'login']);