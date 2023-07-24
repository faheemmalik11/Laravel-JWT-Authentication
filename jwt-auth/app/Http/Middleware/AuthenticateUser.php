<?php

namespace App\Http\Middleware;






use Exception;
use Illuminate\Http\Request;
use Closure;

use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;




class Authenticateuser {

 
    protected $auth;

    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }


    public function handle(Request $request, Closure $next)
    {
       
        try {



            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'user not found', 'user' => $user], 500);
            }

        } catch (Exception $e) {
            return response()->json(['message' => 'token cannot be parsed']);
        }

        if(auth()->check()){
            return $next($request);
        } else {
            return response()->json([
                'status' => auth()->check(),
                'message' => 'Please login with user Account.',
            ], 409);
        }

    }
}