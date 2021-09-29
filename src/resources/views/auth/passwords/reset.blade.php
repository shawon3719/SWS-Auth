<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Register</title>
    <link rel="stylesheet" href="{{asset('vendor/sws/auth/css/auth-style.css')}}">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap-theme.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jquery.bootstrapvalidator/0.5.0/css/bootstrapValidator.min.css">
</head>
<body>
    <div class="container">

        @if(Session::get('success'))
            <div class="alert alert-success alert-dismissible">
                <button type="button" class="close" data-dismiss="alert">&times;</button>
                <strong>Success!</strong> {{ Session::get('success') }}
            </div>
        @endif

        @if(Session::get('failed'))
            <div class="alert alert-danger alert-dismissible">
                <button type="button" class="close" data-dismiss="alert">&times;</button>
                <strong>Sorry!</strong> {{ Session::get('failed') }}
            </div>
        @endif

        @if ($errors->any())
            <div class="alert alert-danger alert-dismissible">
                @foreach ($errors->all() as $error)
                    <button type="button" class="close" data-dismiss="alert">&times;</button>
                    <strong>Sorry!</strong> {{ $error }}
                @endforeach
            </div>
        @endif

        <div id="card">
            <div id="card-content">
              <div id="card-title">
                <h2>RESET PASSWORD</h2>
                <div class="underline-title"></div>
              </div>
              <form class="form-horizontal" action="{{route('auth.reset.password',$token)}}" method="post" id="password_reset_form">
                @csrf
                <fieldset>
                    <input value="{{$email}}" name="email" maxlength="30" placeholder="E-Mail" class="form-control @error('email') is-invalid @enderror" type="hidden">

                    <div class="form-group">
                        <label class="col-md-12">Password</label>
                        <div class="col-md-12 ">
                            <div class="input-group">
                                <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                                <input value="{{ old('password', null) }}" name="password" maxlength="16" placeholder="**********" class="form-control @error('password') is-invalid @enderror" type="password">
                            </div>
                            @if ($errors->has('password'))
                                <small class="text-danger">{{ $errors->first('password') }}</small>
                            @endif
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-md-12">Confirm Password</label>
                        <div class="col-md-12 ">
                            <div class="input-group">
                                <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                                <input value="{{ old('password_confirmation', null) }}" name="password_confirmation" maxlength="16" placeholder="**********" class="form-control @error('password') is-invalid @enderror" type="password">
                            </div>
                            @if ($errors->has('password'))
                                <small class="text-danger">{{ $errors->first('password') }}</small>
                            @endif
                        </div>
                    </div>
    
                    <div class="form-group">
                        <label class="col-md-12 control-label"></label>
                        <div class="col-md-12">
                            <button type="submit" id="submit-btn">Reset</button>
                            <p id="signup">Remembered old password? <a href="{{route('login')}}">Login</a></p>
                        </div>
                    </div>
    
                </fieldset>
            </form>
            </div>
          </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-validator/0.5.3/js/bootstrapValidator.min.js"></script>
    <script src="{{asset('vendor/sws/auth/js/auth-script.js')}}"></script>
</body>
</html>