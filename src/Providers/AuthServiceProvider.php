<?php

namespace SWS\Auth\Providers;

use Illuminate\Support\ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {

        $this->loadRoutesFrom(__DIR__.'/../Routes/web.php');

        $this->publishes([__DIR__.'/../resources/views' => resource_path('views')], 'sws-auth');

        $this->publishes([__DIR__.'/../database/migrations' => database_path('migrations')], 'sws-auth');

        $this->publishes([__DIR__.'/../Models' => app_path('Models')], 'sws-auth');

        $this->publishes([__DIR__.'/../public/css' => public_path('vendor/sws-auth/css')], 'sws-auth');
        $this->publishes([__DIR__.'/../public/js' => public_path('vendor/sws-auth/js')], 'sws-auth');

        $this->publishes([__DIR__.'/../config/sws-auth.php' => config_path('sws-auth.php')], 'sws-auth');

    }

    public function register()
    {

    }

}
