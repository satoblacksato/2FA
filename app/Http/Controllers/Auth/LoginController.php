<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\User;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Auth;
use Hash;
use Google2FA;
use BaconQrCode\Writer as BaconQrCodeWriter;

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
        $user = User::where($this->username(), '=', $request->email)->first();
        if (password_verify($request->password, optional($user)->password)) {
            $this->clearLoginAttempts($request);
            $urlQR='';
            if(is_null($user->token_login)) {
                $user->token_login = Google2FA::generateSecretKey();
                $user->save();

                $bacon = new BaconQrCodeWriter( new ImageRenderer(
                    new RendererStyle(200),
                    new ImagickImageBackEnd()
                ));

                $data = $bacon->writeString(Google2FA::getQRCodeUrl(config('app.name'), $user->email, $user->token_login), 'utf-8');
                $urlQR = 'data:image/png;base64,' . base64_encode($data);
            }
            return view("auth.2fa", compact('urlQR', 'user'));
        }
        $this->incrementLoginAttempts($request);
        return $this->sendFailedLoginResponse($request);
    }

    public function login2FA(Request $request, User $user)
    {
        $this->validate($request, ['code_verification' => 'required']);
        $valid = Google2FA::verifyKey($user->token_login, $request->code_verification, 8);
        if ($valid) {
            $request->session()->regenerate();
            \Illuminate\Support\Facades\Auth::login($user);
            return redirect()->intended($this->redirectPath());

        } else {
            return redirect()->back()->withErrors(['error' => 'Codigo de verificación incorrecto']);
        }
    }

}
