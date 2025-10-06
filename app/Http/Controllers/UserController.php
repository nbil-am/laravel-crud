<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\PersonalAccessToken;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $validated = $request->validate([
            'full_name' => 'required|string|max:225',
            'username'  => 'required|string|max:225',
            'email'     => 'required|string|email|max:225|unique:users',
            'password'  => 'required|string|min:8|max:225|confirmed',
        ]);

        $user = User::create([
            'full_name' => $validated['full_name'],
            'username'  => $validated['username'],
            'email'     => $validated['email'],
            'password'  => Hash::make($validated['password']),
        ]);
        $user = User::where('email', $validated['email'])->first();

        // Buat token setelah register
        $refresh_token = $user->createToken('refresh_token')->plainTextToken;
        $front_token   = $user->createToken('front_token', ['*'], now()->addMinutes(20))->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully',
            'user'    => $user,
        ], 201)
            ->cookie('refresh_token', $refresh_token, 60 * 24 * 7, '/', null, false, true)
            ->cookie('front_token', $front_token, 20, '/', null, false, false);
    }

    public function login(Request $request)
    {
        $validated = $request->validate([
            'nameail'  => 'required|string', // email atau username
            'password' => 'required|string',
        ]);

        // Cek apakah pakai email atau username
        $loginType = filter_var($validated['nameail'], FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        $user = User::where($loginType, $validated['nameail'])->first();

        if (!$user || !Hash::check($validated['password'], $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        // Generate 2 token baru
        $refresh_token = $user->createToken('refresh_token')->plainTextToken;
        $front_token   = $user->createToken('front_token', ['*'], now()->addMinutes(20))->plainTextToken;

        return response()->json([
            'message' => 'Login successful',
            'user'    => $user,
        ], 200)
            ->cookie('refresh_token', $refresh_token, 60 * 24 * 7, '/', null, false, true)
            ->cookie('front_token', $front_token, 20, '/', null, false, false);
    }

    public function logout(Request $request)
    {
        $user = $request->user();

        if ($user) {
            $user->tokens()->delete();
        }

        return response()->json(['message' => 'Logged out successfully'], 200)
            ->cookie('refresh_token', '', -1, '/')
            ->cookie('front_token', '', -1, '/');
    }


public function refreshToken(Request $request)
{
    $refreshToken = $request->cookie('refresh_token');

    if (!$refreshToken) {
        return response()->json(['message' => 'No refresh token provided'], 401);
    }

    // Pisahkan ID dan token dari format "id|token"
    $parts = explode('|', $refreshToken, 2);
    if (count($parts) !== 2) {
        return response()->json(['message' => 'Invalid token format'], 400);
    }

    [$id, $token] = $parts;

    // Cari token di database
    $tokenModel = PersonalAccessToken::find($id);

    if (!$tokenModel || !hash_equals($tokenModel->token, hash('sha256', $token))) {
        return response()->json(['message' => 'Invalid or expired refresh token'], 401);
    }

    // Ambil user terkait token tersebut
    $user = $tokenModel->tokenable;

    if (!$user) {
        return response()->json(['message' => 'User not found'], 404);
    }

    // Buat front_token baru (misal expired 20 menit)
    $newFrontToken = $user->createToken('front_token', ['*'], now()->addMinutes(20))->plainTextToken;

    return response()->json([
        'message' => 'Token refreshed successfully',
    ])->cookie('front_token', $newFrontToken, 20, '/', null, false, false);
}

    public function isLogin(Request $request) {
        return response()->json(['message'=>'User is logged in','user'=>$request->user()]);
    }
}
