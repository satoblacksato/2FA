<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Auth;
use Hash;
use Sonata\GoogleAuthenticator\GoogleQrUrl;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }


    public function login(Request $request)
    {
        $this->validateLogin($request);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }
        $user=User::where($this->username(),'=', $request->email)->first();
        if ( password_verify($request->password, optional($user)->password)) {
            $this->clearLoginAttempts($request);
            $user->token_login='JM3GEUCOJIZWSRCRKJLFAQ3MPJJXEVD2UCFMG4AWOM7U3ANRMACYWOAA7VTBDTAG';//strtoupper(str_random(15));
            $user->save();
            $urlQR=  GoogleQrUrl::generate($user->email,$user->token_login);
            return view("auth.2fa",compact('urlQR','user'));
        }
        $this->incrementLoginAttempts($request);
        return $this->sendFailedLoginResponse($request);
    }

    public function login2FA(Request $request,User $user){
        $this->validate($request,['code_verification'=>'required']);
        $googleAUTH  = new \Google\Authenticator\GoogleAuthenticator();
        if ($googleAUTH->checkCode($user->token_login,$request->code_verification)) {
            $request->session()->regenerate();
            \Illuminate\Support\Facades\Auth::login($user);
            return  redirect()->intended($this->redirectPath());


        } else {
           return redirect()->back()->withErrors(['error'=>'Codigo de verificación incorrecto']);
        }
    }

}
