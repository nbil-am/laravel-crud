<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function isLogin()
    {
        return response()->json(['message' => 'User is logged in'], 200);
    }
    public function register(Request $request)
    {
        $validated = $request->validate([
            'full_name' => 'required|string|max:225',
            'username' => 'required|string|max:225',
            'email' => 'required|string|email|max:225|unique:users',
            'password' => 'required|string|min:8|max:225|confirmed',
        ]);
        $user = User::create([
            'full_name' => $validated['full_name'],
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);
        $credentials = $request->only('email', 'password');
        Auth::attempt($credentials);
        $user = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;
        return response()->json(['message' => 'User registered successfully', 'user' => $user, 'token' => $token], 201);
    }
    public function login(Request $request)
    {
        $request->validate([
            'nameail' => 'required|string',
            'password' => 'required|string',
        ]);

        // tentukan kolom yang dipakai
        $loginType = filter_var($request->input('nameail'), FILTER_VALIDATE_EMAIL) ? 'email' : 'name';

        $credentials = [
            $loginType => $request->input('nameail'),
            'password' => $request->input('password'),
        ];

        if (Auth::attempt($credentials)) {
            $user = Auth::user();
            $token = $user->createToken('auth_token')->plainTextToken;
            return response()->json(['message' => 'Login successful', 'token' => $token], 200);
        }

        return response()->json(['message' => 'The provided credentials do not match our records.'], 422);
    }

}

