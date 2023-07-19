# Laravel-JWT-Authentication
Complete tutorial for Laravel JWT Authentication

## Steps
*[Installing jwt](#install_jwt)
*[Publishing the Config](#publish_config)
*[Generate secret key](#generate_secret_key)
*[Updating User model](#update_user_model)
*[Configure Auth guard](#configure_auth_guard)
*[Adding authentication routes](#add_authentication_routes)
*[Creating the AuthController](#create_auth_controller)
*[Middleware(Optional)](#middleware)




### Installing jwt
You can download jwt from any source not necessarily this one: 
```sh
composer require php-open-source-saver/jwt-auth
```

### Publishing the Config
```sh
php artisan vendor:publish --provider="PHPOpenSourceSaver\JWTAuth\Providers\LaravelServiceProvider"
```

### Generate secret key
```sh
php artisan jwt:secret
```

### Updating User model

Firstly you need to implement the PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject or from you have download jwt contract on your User model, which requires that you implement the 2 methods getJWTIdentifier() and getJWTCustomClaims().

Add the line:
```sh
use PHPOpenSourceSaver\JWTAuth\Contracts\JWTSubject;
```

Change the user model class to:
```sh
class User extends Authenticatable implements JWTSubject
```

Add these two methods:
```sh
public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }
```

### Configure Auth guard

Inside the config/auth.php file you will need to make a few changes to configure Laravel to use the jwt guard to power your application authentication.
Make the following changes to the file:
```sh
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

You can define other guard than api and you can also define other passwords and provider too. But for this, you have to change overall config file and define all one by one.


### Adding authentication routes

Make a folder named api in the routes if you want. Then, add some routes in routes/api/api.php as follows:
But before making the routes make sure you have defined them in app/Providers/RouteServiceProvider.php like:

```sh
 Route::middleware('api')
                ->prefix('api')
                ->group(base_path('routes/api/api.php'));

            Route::middleware('api')
            ->prefix('auth')
            ->group(base_path('routes/api/auth.php'));
```

After this make the routes in the file auth.php:
```sh
    Route::post('login', 'AuthController@login');
    Route::middleware(['auth:api'])->group(function () {
        Route::post('logout', [AuthController::class, 'logout']);
        Route::post('refresh', [AuthController::class, 'refresh']);
        Route::post('me', [AuthController::class, 'me']);
    });
```


### Creating the AuthController

Now you have to make AuthController:
```sh
php artisan make:controller AuthController
```

AuthController.php:
```sh
<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}
```

### Middleware(Optional)

If you do not want default auth middleware. You can always make your own middleware to authenticate requests. like so:

```sh
<?php

namespace App\Http\Middleware;






use Illuminate\Http\Request;
use Closure;

use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;




class Authenticateuser {

    /**
     * The JWT Authenticator.
     *
     * @var \Tymon\JWTAuth\JWTAuth
     */
    protected $auth;

    public function __construct(JWTAuth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
    {
       
        try {



            $user = JWTAuth::parseToken()->authenticate();

            if (!$user) {
                return response()->json(['message' => 'user not found', 'user' => $user], 500);
            }

        } catch (JWTException $e) {
            return response()->json(['messages' => $e->getMessage()], 500);
        }

        if(auth()->guard('user')->check()){
            return $next($request);
        } else {
            return response()->json([
                'status' => auth()->guard('user')->check(),
                'message' => 'Please login with user Account.',
            ], 409);
        }

    }
}
```

You can change it according to need. But after doing this you have to change middleware in routes from auth:api to whatever you name it. Also don't forget to define the middleware in Kernel.php