<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ScanController;

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
Route::get('checkTools', [ScanController::class, 'checkTools']);
Route::get('scan-website', [ScanController::class, 'checkToolsQueue']);
Route::get('get-scan-result', [ScanController::class, 'getScanResult']);



