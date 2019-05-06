<?php

Route::group(['namespace' => 'Api'], function () {
    Route::any('yzy/create', 'YzyController@create');
    Route::resource('yzy', 'YzyController');
    Route::resource('trimepay', 'TrimepayController');

    // 定制客户端
    Route::any('login', 'LoginController@login');
    // 
    Route::any('register', 'LoginController@register');
    Route::any('updateProxy', 'LoginController@updateProxy');
    Route::any('updateVersion', 'LoginController@updateVersion');    
    Route::any('updatecard', 'LoginController@UpdateCard');
// PING检测
    Route::get('ping', 'PingController@ping');
});
