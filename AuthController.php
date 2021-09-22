<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|alpha_num|between:5,100',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            $res = array(
                'message' => array('validation_err' => $validator->errors()),
                'data' => [],
                'status' => 0
            );
            return response()->json($res, 422);
        }

        try {
            if (!$token = auth()->attempt($validator->validated())) {
                // return response()->json(['error' => 'Unauthorized'], 401);
                $res = array(
                    'message' => array('authorization_err' => $validator->errors()),
                    'data' => [],
                    'status' => 0
                );
                return response()->json($res, 401);
            }

            $res = array(
                'message' => 'Login successfully',
                'data' => $this->createNewToken($token),
                'status' => 1
            );
            return response()->json($res, 200);
        } catch (\Throwable $e) {
            $res = array(
                'message' => $e->getMessage(),
                'data' => array(),
                'status' => 0
            );
            return response()->json($res, 400);
        }
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'first_name' => 'string',
            'last_name' => 'string',
            'dob' => 'string',
            'phone' => 'string',
            'address' => 'string',
            'gender' => 'string',
            'username' => 'required|string|alpha_num|between:5,100|unique:users',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if ($validator->fails()) {
            $res = array(
                'message' => array('validation_err' => $validator->errors()),
                'data' => [],
                'status' => 0
            );
            return response()->json($res, 422);
        }

        try {
            $user = User::create(array_merge(
                $validator->validated(),
                ['password' => bcrypt($request->password)]
            ));

            $res = array(
                'message' => 'User successfully registered',
                'data' => array('user_details' => $user),
                'status' => 1
            );
            return response()->json($res, 200);
        } catch (\Throwable $e) {
            $res = array(
                'message' => $e->getMessage(),
                'data' => array(),
                'status' => 0
            );
            return response()->json($res, 400);
        }
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        $res = array(
            'message' => 'User successfully signed out',
            'data' => [],
            'status' => 1
        );
        return response()->json($res, 200);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile()
    {
        $res = array(
            'message' => 'User Profile',
            'data' => array('user_details' => auth()->user()),
            'status' => 1
        );
        return response()->json($res, 200);
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }
}
