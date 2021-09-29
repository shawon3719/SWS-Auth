<!DOCTYPE html>
<html>
<head>
    <title>Welcome to {{ config('app.name', 'Laravel') }}</title>
</head>
<body>
    <p>Hello, </p>
    <h1>{{ $user->name }}</h1>
    <p>Thank you for registering here.</p>
    <p>Please verify your email with following link: 
        <a href="{{ route('auth.email.verify', $token) }}">Verify Email.</a>
    </p>
</body>
</html>