<?php

Route::group(['middleware' => ['web'], 'namespace'=>'SWS\Auth\Http\Controllers'], function(){

    Route::get('permissions', 'AuthController@Permission')->name('permission');

    
    Route::get('register', 'AuthController@index')->name('register');
    Route::post('register', 'AuthController@register')->name('auth.register.store');

    Route::get('login', 'AuthController@loginIndex')->name('login');
    Route::post('login', 'AuthController@postLogin')->name('auth.login.check');

    Route::get('forgot-password', 'AuthController@forgotPassword')->name('auth.forgot.password.index');
    Route::post('forgot-password', 'AuthController@postForgotPassword')->name('auth.forgot.password');
    Route::get('reset-password/{token}', 'AuthController@resetPassword')->name('auth.reset.password.index');
    Route::post('reset-password/{token}', 'AuthController@postResetPassword')->name('auth.reset.password');

    Route::get('logout', 'AuthController@logout')->name('auth.logout');
    Route::get('user-verify/{token}', 'AuthController@verifyEmail')->name('auth.email.verify');

});

Route::group(['middleware' => 'role:user'], function() {

    Route::get('/user', function() {
 
       return 'Welcome...!!';
       
    });
 
 });
