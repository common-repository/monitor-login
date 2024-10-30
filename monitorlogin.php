<?php
/**
 * Plugin Name: Monitor Login
 * Description: Every time than a user log into your website you will receive a simple email notify this.
 * Author: TocinoDev
 * Author URI: https://tocino.mx
 * Version: 0.1.5
 * Tested up to: 6.1
 * Requires PHP: 7.4
 */
use MonitorLogin\App as MonitorLoginApp;

defined('ABSPATH') || exit();

if(!defined('MONITORLOGIN_FILE')){
	define('MONITORLOGIN_FILE', __FILE__);
}
if(!defined('MONITORLOGIN_URL')){
	define('MONITORLOGIN_URL', plugin_dir_url(MONITORLOGIN_FILE));
}

require 'vendor/autoload.php';

MonitorLoginApp::boot();