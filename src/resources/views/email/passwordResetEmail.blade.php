<!DOCTYPE html>
<html>
<head>
    <title>Welcome to {{ config('app.name', 'Laravel') }}</title>
</head>
<body>
    <p>Hello</p>
    <p>Please clcik the following link to reset your password: 
        <a href="{{ route('auth.reset.password.index', $token) }}">Reset Your Password.</a>
    </p>
</body>
</html>