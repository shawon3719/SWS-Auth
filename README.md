## SWS Auth

#### SWS Auth is a Complete Build of Laravel 8 with Email Registration Verification. Built on Bootstrap 4.
[![Build Status](https://travis-ci.org/jeremykenedy/laravel-auth.svg?branch=master)](https://travis-ci.org/jeremykenedy/laravel-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

 ### About
<table>
    <tr>
        <td>
            <img src="https://cdn.auth0.com/styleguide/components/1.0.8/media/logos/img/badge.png" alt="Auth0" width="50">
        </td>
        <td>
            Laravel 8 with user authentication and registration with email confirmation. Uses official [Bootstrap 4](https://getbootstrap.com). This also makes full use of Controllers for the routes and templates for the views. Project can be stood up in minutes.
        </td>
    </tr>
</table>

### Features
#### A [Laravel](https://laravel.com/) 8.x with [Bootstrap](https://getbootstrap.com) 4.x project.

| Laravel Auth Features  |
| :------------ |
|Built on [Laravel](https://laravel.com/) 8|
|Built on [Bootstrap](https://getbootstrap.com/) 4|
|Uses [MySQL](https://github.com/mysql) Database (can be changed)|
|Uses [Artisan](https://laravel.com/docs/master/artisan) to manage database migration, schema creations, and create/publish page controller templates|
|Dependencies are managed with [COMPOSER](https://getcomposer.org/)|
|Makes use of [Laravel's Soft Delete Structure](https://laravel.com/docs/master/eloquent#soft-deleting)|
|Soft Deleted Users Management System|

### Installation Instructions
1. run :
```
composer require sws/smartauth --v.1.1

```
2. add ```auth``` provider to your ```config/app.php``` ```\SWS\Auth\Providers\AuthServiceProvider::class,```
3. Setup your email configuration to your `.env` file
4. From the projects root folder run:
```
php artisan vendor:publish --tag=auth

```

#### Optionally Build Cache
1. From the projects root folder run `php artisan config:cache`


### Routes

```bash
+--------+----------+------------------------+----------------------------+------------------------------------------------------------------+---------------------------------------------+
| Domain | Method   | URI                    | Name                       | Action                                                           | Middleware                                  |
+--------+----------+------------------------+----------------------------+------------------------------------------------------------------+---------------------------------------------+
|        | GET|HEAD | /                      | home                       | Closure                                                          | web                                         |
|        | GET|HEAD | api/user               |                            | Closure                                                          | api                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\Authenticate:sanctum    |
|        | POST     | forgot-password        | auth.forgot.password       | sws\smartauth\Http\Controllers\AuthController@postForgotPassword | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | GET|HEAD | forgot-password        | auth.forgot.password.index | sws\smartauth\Http\Controllers\AuthController@forgotPassword     | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | GET|HEAD | login                  | auth.login.index           | sws\smartauth\Http\Controllers\AuthController@loginIndex         | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | POST     | login                  | auth.login.check           | sws\smartauth\Http\Controllers\AuthController@postLogin          | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | GET|HEAD | logout                 | auth.logout                | sws\smartauth\Http\Controllers\AuthController@logout             | web                                         |
|        | GET|HEAD | register               | auth.register.index        | sws\smartauth\Http\Controllers\AuthController@index              | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | POST     | register               | auth.register.store        | sws\smartauth\Http\Controllers\AuthController@register           | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | GET|HEAD | reset-password/{token} | auth.reset.password.index  | sws\smartauth\Http\Controllers\AuthController@resetPassword      | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | POST     | reset-password/{token} | auth.reset.password        | sws\smartauth\Http\Controllers\AuthController@postResetPassword  | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
|        | GET|HEAD | sanctum/csrf-cookie    |                            | Laravel\Sanctum\Http\Controllers\CsrfCookieController@show       | web                                         |
|        | GET|HEAD | user-verify/{token}    | auth.email.verify          | sws\smartauth\Http\Controllers\AuthController@verifyEmail        | web                                         |
|        |          |                        |                            |                                                                  | App\Http\Middleware\RedirectIfAuthenticated |
+--------+----------+------------------------+----------------------------+------------------------------------------------------------------+---------------------------------------------+

```

### File Tree
```
auth
├── src
│   ├── config
│   │   └── auth.php
│   ├── database
│   │   └── migrations
│   │       └── create_users_table.php
│   ├── Http
│   │   ├── Controllers
│   │   │   └── AuthController.php
│   │   └── Requests
│   │       └── ResetPasswordRequest.php
│   │       └── StoreUserRequest.php
│   ├── Models
│   │   └── Auth.php
│   ├── Providers
│   │   └── AuthServiceProvider.php
│   ├── Public
│   │   ├── css
│   │   │   └── auth-style.css
│   │   └── js
│   │       └── auth-script.js
│   ├── Resources
│   │   ├── views
│   │   │   └── Auth
│   │   │       ├── passwords
│   │   │       │   ├── forgot.blade.php
│   │   │       │   └── reset.blade.php
│   │   │       ├── login.blade.php
│   │   │       └── register.blade.php
│   │   └── Email
│   │       ├── passwordResetEmail.blade.php
│   │       └── userVerificationEmail.blade.php
│   ├── Routes
│   │   └── web.php
│   ├── Services
│   │   └── AuthService.php
├── vendor
│   ├── composer
│   │   └── installed.json
│   ├── autoload.php
│   └── composer.json
├── composer.json
├── LICENSE
└── README.md

```

### SWS Auth License
auth is licensed under the [MIT license](https://opensource.org/licenses/MIT). Enjoy!

### Contributors
* Thanks goes to these [wonderful people](https://github.com/shawon3719/pacakge-custom-auth/graphs/contributors):
* Please feel free to contribute and make pull requests!



