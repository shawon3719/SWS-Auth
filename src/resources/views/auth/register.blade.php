<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Register</title>
    <link rel="stylesheet" href="{{asset('vendor/sws-auth/css/sws-auth-style.css')}}">
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
                <h2>REGISTER</h2>
                <div class="underline-title"></div>
              </div>
              <form class="form-horizontal" action="{{route('auth.register.store')}}" method="post" id="registration_form">
                @csrf
                <fieldset>
                    <div class="form-group">
                        <label class="col-md-12">Name</label>
                        <div class="col-md-12 ">
                                <div class="input-group">
                                    <span class="input-group-addon"><i class="glyphicon glyphicon-user"></i></span>
                                    <input value="{{ old('name', null) }}" name="name" maxlength="30" placeholder="Name" class="form-control @error('name') is-invalid @enderror" type="text" onkeypress="return (event.charCode > 64 && event.charCode < 91) || (event.charCode > 96 && event.charCode < 123)" >
                                </div>
                                @if ($errors->has('name'))
                                    <small class="text-danger">{{ $errors->first('name') }}</small>
                                @endif
                        </div>
                    </div>
    
                    <div class="form-group">
                        <label class="col-md-12">E-mail</label>
                        <div class="col-md-12 ">
                            <div class="input-group">
                                <span class="input-group-addon"><i class="glyphicon glyphicon-envelope"></i></span>
                                <input name="email" value="{{ old('email', null) }}" maxlength="30" placeholder="E-Mail" class="form-control @error('email') is-invalid @enderror" type="text">
                            </div>
                            @if ($errors->has('email'))
                                <small class="text-danger">{{ $errors->first('email') }}</small>
                            @endif
                        </div>
                    </div>

                    <div class="form-group">
                        <label class="col-md-12">Password</label>
                        <div class="col-md-12 ">
                            <div class="input-group">
                                <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                                <input name="password" value="{{ old('password', null) }}" maxlength="16" placeholder="**********" class="form-control @error('password') is-invalid @enderror" type="password">
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
                            <button type="submit" id="submit-btn">Sign-up</button>
                            <p id="signup">Already have an account? <a href="{{route('login')}}">Login</a></p>
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
    <script src="{{asset('vendor/sws-auth/js/sws-auth-script.js')}}"></script>

</body>
</html>