<?php

namespace App\Http\Controllers;

use App\Notifications\SignupActivate;
use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Storage;
use Laravolt\Avatar\Facade;

class AuthController extends Controller
{
    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed',
        ]);

        $user = new User($request->except('_token'));
        $user->password = bcrypt($user->password);
        $user->activation_token = str_random(60);
        $user->save();

        $avatar = Facade::create($user->name)->getImageObject()->encode('png');
        Storage::disk('public')->put('avatars/' . $user->id . '/avatar.png', (string) $avatar);

        $user->notify(new SignupActivate());

        return response()->json(['message' => 'Successfully created.'], Response::HTTP_CREATED);
    }

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string'
        ]);

        $credentials = $request->only(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;

        if (!auth()->attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        /** @var User $user */
        $user = $request->user();

        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->get('remember_me')) {
            $token->expires_at = Carbon::now()->addWeek();
        }
        $token->save();

        return \response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString()
        ]);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        \request()->user()->token()->revoke();

        return \response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    public function user()
    {
        return \response()->json(\request()->user());
    }

    /**
     * @param $token
     * @return \Illuminate\Http\JsonResponse
     */
    public function signupActivate($token)
    {
        /** @var User $user */
        $user = User::where('activation_token', $token)->first();

        if (!$user) {
            return \response()->json(['message' => 'This activation token is invalid.'], Response::HTTP_NOT_FOUND);
        }

        $user->activeAccount();

        return \response()->json($user);
    }
}
