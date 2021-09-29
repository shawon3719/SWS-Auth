<?php

namespace SWS\Auth\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Session;
use SWS\Auth\Http\Requests\ResetPasswordRequest;
use SWS\Auth\Http\Requests\StoreUserRequest;
use SWS\Auth\Services\AuthService;

class AuthController extends Controller
{

    protected $authService;

    public function __construct()
    {
        $this->authService = new AuthService(); 
        $this->middleware('guest', ['except' => 'logout']);
    }

    public function index()
    {
        return view('auth.register');
    }

    public function loginIndex()
    {
        return view('auth.login');
    }

    public function postLogin(Request $request)
    {
        $request->validate([
            'email'=>'required|email',
            'password'=>'required|min:8'
       ]);

        if(User::loginAttempt($request)){
            $request->session()->flash('success', 'You have successfully Logged-In.');
            return redirect('/');
        }else{
            return redirect()->back();
        };

    }

    public function logout(){
        if(session()->has('LoggedUser')){
            session()->pull('LoggedUser');
            return redirect()->route('login');
        }
    }

    public function register(StoreUserRequest $request)
    {
        
        $this->authService->register($request);

        return redirect()->route('login');
    }


    public function verifyEmail($token)
    {
        $data = $this->authService->verifyEmail($token);
  
        return redirect()->route('login')->with($data['type'], $data['message']);
    }


    public function forgotPassword(){
        return view('auth.passwords.forgot');
    }

    public function postForgotPassword(Request $request){

        $this->authService->forgotPassword($request);
        
        return redirect()->route('auth.forgot.password');
    }

    public function resetPassword($token){

        $data['token'] = $token;

        $data['email'] = Crypt::decrypt($token);

        $email_exist = User::where('email', $data['email'])->first();

        if($email_exist){
            return view('auth.passwords.reset', $data);
        }else{
            return redirect()->route('login')->with('failed', 'We did not found your email in our system.');
        }
    }

    public function postResetPassword(ResetPasswordRequest $request){

        $password_reset = $this->authService->resetPassword($request);

        if($password_reset){
            return redirect()->route('login');
        }else{
            return redirect()->back();
        }
        
    }
}