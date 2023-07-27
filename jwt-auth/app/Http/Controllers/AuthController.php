<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('authUser', ['except' => ['login','refresh']]); //auth middleware is applied to all the function except login. Check App\Http\Middleware\Authenticate.php for middleware
    }

    public function login()
    {
        $credentials = request(['email', 'password']);  // email and password is fetched through request

        if (! $token = auth()->attempt($credentials)) {  //  check if the credentials are correct
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token); // token is sent in response and user is logged in
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());  //give the current logged in user info
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();  //logout the user

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());  //refresh token and send in response
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token) // function to return token in response
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}


