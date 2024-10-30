<?php
namespace MonitorLogin;

use Browser;

class App
{
	private static $instance = null;

	public function __construct()
	{
		register_activation_hook(MONITORLOGIN_FILE, array($this, 'install'));
		register_deactivation_hook(MONITORLOGIN_FILE, array($this, 'uninstall'));

		add_action('admin_init', array($this, 'register_settings'));
		add_action('admin_menu', array($this, 'register_admin_menu'));

		add_action('wp_login', array($this, 'send_login_alert'), 20, 2);
		add_action('activated_plugin', array($this, 'send_activate_plug_alert'), 20, 2);
		add_action('deactivated_plugin', array($this, 'send_deactivate_plug_alert'), 20, 2);
		add_action('deleted_plugin', array($this, 'send_deleted_plug_alert'), 20, 2);
		add_action('switch_theme', array($this, 'send_switch_theme_alert'), 20, 3);
	}

	/**
	 * Boot the application
	 */
	public static function boot()
	{
		if(static::$instance === null){
			static::$instance = new static();
		}
	}

	/**
	 * @param 
	 */
	public function get_inet_pton($inet_pton)
	{
		// IPv4
		if (preg_match('/^(?:\d{1,3}(?:\.|$)){4}/', $ip)) {
			$octets = explode('.', $ip);
			$bin = chr($octets[0]) . chr($octets[1]) . chr($octets[2]) . chr($octets[3]);
			return $bin;
		}

		// IPv6
		if (preg_match('/^((?:[\da-f]{1,4}(?::|)){0,8})(::)?((?:[\da-f]{1,4}(?::|)){0,8})$/i', $ip)) {
			if ($ip === '::') {
				return "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
			}
			$colon_count = substr_count($ip, ':');
			$dbl_colon_pos = strpos($ip, '::');
			if ($dbl_colon_pos !== false) {
				$ip = str_replace('::', str_repeat(':0000',
						(($dbl_colon_pos === 0 || $dbl_colon_pos === strlen($ip) - 2) ? 9 : 8) - $colon_count) . ':', $ip);
				$ip = trim($ip, ':');
			}

			$ip_groups = explode(':', $ip);
			$ipv6_bin = '';
			foreach ($ip_groups as $ip_group) {
				$ipv6_bin .= pack('H*', str_pad($ip_group, 4, '0', STR_PAD_LEFT));
			}

			return strlen($ipv6_bin) === 16 ? $ipv6_bin : false;
		}

		// IPv4 mapped IPv6
		if (preg_match('/^(?:\:(?:\:0{1,4}){0,4}\:|(?:0{1,4}\:){5})ffff\:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i', $ip, $matches)) {
			$octets = explode('.', $matches[1]);
			return "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" . chr($octets[0]) . chr($octets[1]) . chr($octets[2]) . chr($octets[3]);
		}

		return false;
	}

	/**
	 * @param 	string 		$remote_addr
	 */
	public function get_host($remote_addr)
	{
		$host = false;
		if(function_exists('gethostbyaddr')){
			$host = @gethostbyaddr($remote_addr);
		}
		if(!$host){
			$ptr = false;
			if (filter_var($remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
				$ptr = implode(".", array_reverse(explode(".", $remote_addr))) . ".in-addr.arpa";
			} else if (filter_var($remote_addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
				$inet_pton = $this->get_inet_pton($remote_addr);
				$ptr = implode(".", array_reverse(str_split(bin2hex($inet_pton)))) . ".ip6.arpa";
			}

			if ($ptr && function_exists('dns_get_record')) {
				$host = @dns_get_record($ptr, DNS_PTR);
				if ($host) {
					$host = $host[0]['target'];
				}
			}
		}
		if(!$host){
			$host = 'NONE';
		}
		return $host;
	}

	private function get_gate()
	{
		$gate = 'wp-login.php';
		if(isset($GLOBALS['wp_xmlrpc_server']) && is_object($GLOBALS['wp_xmlrpc_server'])){
			$gate = 'xml_rpc';
		}

		return $gate;
	}

	private function is_vpn_or_proxy($host)
	{
		return filter_var($host, FILTER_VALIDATE_IP) ? true : false;
	}

	/** 
	 * @param 	string 		$username
	 * @param  	WP_User 	$user
	 */
	public function send_login_alert($username, $user)
	{
		$browser = new Browser();
		$remote_addr = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
		$current_browser = $browser->getBrowser();
		$platform = $browser->getPlatform();
		$host = $this->get_host($remote_addr);
		$blogname = get_bloginfo('name');
		$gate = $this->get_gate();
		$mailto = get_option('monitorlogin_email');
		$is_vpn_or_proxy = $this->is_vpn_or_proxy($host);
		if(!$mailto)
			return;
		wp_mail(
			$mailto, 
			"[Alert] Login access to your website: ".esc_html($blogname), 
			$this->get_login_tmpl(
				$blogname, 
				$username, 
				$remote_addr, 
				$gate, 
				$current_browser, 
				$platform, 
				$host, 
				$is_vpn_or_proxy
			), 
			array('Content-Type: text/html; charset=UTF-8')
		);
	}

	/**
	 * @param 	string 		$plugin
	 * @param 	bool 		$network_wide
	 */
	public function send_activate_plug_alert($plugin, $network_wide)
	{
		$monitorplugs = get_option('monitorlogin_plugs');
		if($monitorplugs == 'no')
			return;

		$mailto = get_option('monitorlogin_email');
		if(!$mailto)
			return;

		$plugin = explode('/', $plugin);
		$plugin = isset($plugin[1]) ? $plugin[1] : $plugin[0];
		$plugin = explode('.', $plugin);
		$plugin = $plugin[0];

		$user = wp_get_current_user();
		$blogname = get_bloginfo('name');
		$gate = $this->get_gate();
		$remote_addr = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
		$browser = new Browser();
		$current_browser = $browser->getBrowser();
		$platform = $browser->getPlatform();
		$host = $this->get_host($remote_addr);
		$is_vpn_or_proxy = $this->is_vpn_or_proxy($host);

		wp_mail(
			$mailto,
			"[Alert] Plugin activation on your website: ".esc_html($blogname),
			$this->get_plug_tmpl(
				"activated", 
				$blogname, 
				$plugin, 
				$user->user_login, 
				$remote_addr, 
				$current_browser, 
				$platform, 
				$host, 
				$is_vpn_or_proxy
			),
			array('Content-Type: text/html; charset=UTF-8')	
		);
	}

	/**
	 * @param 	string 		$plugin
	 * @param 	bool 		$network_deactivating
	 */
	public function send_deactivate_plug_alert($plugin, $network_deactivating)
	{
		$monitorplugs = get_option('monitorlogin_plugs');
		if($monitorplugs == 'no')
			return;

		$mailto = get_option('monitorlogin_email');
		if(!$mailto)
			return;

		$plugin = explode('/', $plugin);
		$plugin = isset($plugin[1]) ? $plugin[1] : $plugin[0];
		$plugin = explode('.', $plugin);
		$plugin = $plugin[0];

		$user = wp_get_current_user();
		$blogname = get_bloginfo('name');
		$gate = $this->get_gate();
		$remote_addr = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
		$browser = new Browser();
		$current_browser = $browser->getBrowser();
		$platform = $browser->getPlatform();
		$host = $this->get_host($remote_addr);
		$is_vpn_or_proxy = $this->is_vpn_or_proxy($host);

		wp_mail(
			$mailto,
			"[Alert] Plugin deactivation on your website: ".esc_html($blogname),
			$this->get_plug_tmpl(
				"deactivated", 
				$blogname, 
				$plugin, 
				$user->user_login, 
				$remote_addr, 
				$current_browser, 
				$platform, 
				$host, 
				$is_vpn_or_proxy
			),
			array('Content-Type: text/html; charset=UTF-8')	
		);
	}

	/**
	 * @param 	string 		$plugin_file
	 * @param 	bool 		$deleted
	 */
	public function send_deleted_plug_alert($plugin_file, $deleted)
	{
		$monitorplugs = get_option('monitorlogin_plugs');
		if($monitorplugs == 'no')
			return;

		$mailto = get_option('monitorlogin_email');
		if(!$mailto)
			return;

		$plugin = explode('/', $plugin_file);
		$plugin = isset($plugin[1]) ? $plugin[1] : $plugin[0];
		$plugin = explode('.', $plugin);
		$plugin = $plugin[0];

		$user = wp_get_current_user();
		$blogname = get_bloginfo('name');
		$gate = $this->get_gate();
		$remote_addr = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
		$browser = new Browser();
		$current_browser = $browser->getBrowser();
		$platform = $browser->getPlatform();
		$host = $this->get_host($remote_addr);
		$is_vpn_or_proxy = $this->is_vpn_or_proxy($host);

		wp_mail(
			$mailto,
			"[Alert] Plugin deleted on your website: ".esc_html($blogname),
			$this->get_plug_tmpl(
				"deleted", 
				$blogname, 
				$plugin, 
				$user->user_login, 
				$remote_addr, 
				$current_browser, 
				$platform, 
				$host, 
				$is_vpn_or_proxy
			),
			array('Content-Type: text/html; charset=UTF-8')	
		);
	}

	/**
	 * @param 		string 		$new_name
	 * @param 		WP_Theme 	$new_theme
	 * @param 		WP_Theme 	$old_theme
	 */
	public function send_switch_theme_alert($new_name, $new_theme, $old_theme)
	//public function send_switch_theme_alert($new_theme, $old_theme)
	{
		$monitorthemes = get_option('monitorlogin_themes');
		if($monitorthemes == 'no')
			return;

		$mailto = get_option('monitorlogin_email');
		if(!$mailto)
			return;

		$old_name = $old_theme->get('Name');

		$user = wp_get_current_user();
		$blogname = get_bloginfo('name');
		$gate = $this->get_gate();
		$remote_addr = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP);
		$browser = new Browser();
		$current_browser = $browser->getBrowser();
		$platform = $browser->getPlatform();
		$host = $this->get_host($remote_addr);
		$is_vpn_or_proxy = $this->is_vpn_or_proxy($host);

		wp_mail(
			$mailto,
			"[Alert] Switch theme on your website: ".esc_html($blogname),
			$this->get_theme_tmpl(
				$blogname, 
				$new_name,
				$old_name, 
				$user->user_login, 
				$remote_addr, 
				$current_browser, 
				$platform, 
				$host, 
				$is_vpn_or_proxy
			),
			array('Content-Type: text/html; charset=UTF-8')	
		);
	}

	private function get_login_tmpl($blogname, $username, $remote_addr, $gate, $current_browser, $platform, $host, $is_vpn_or_proxy)
	{
ob_start();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<style>
.body{
	background: #f0f0f1;
	color: #718096;
	width: 100%;
	text-align: center;
}
.container{
	width: 100%;
}
.data{
	width: 570px;
	margin: 0 auto;
	background-color: #dde5ed;
	padding: 10px 20px;
	margin-top: 20px;
}
.text-center{
	text-align: center;
}
@media(max-width: 480px){
	.data{
		width: 100%;
	}
}
</style>
</head>
<body>
	<div class="container">
		<div class="data">
			<p class="text-center">Login Access to your website: <strong><?php echo esc_html($blogname); ?></strong></p>
			<p>The User: <strong><?php echo esc_html($username); ?></strong></p>
			<p>From Gate: <strong><?php echo esc_html($gate); ?></strong></p>
			<p>Has logged from the IP: <strong><?php echo esc_html($remote_addr); ?></strong></p>
			<p>Browser: <strong><?php echo esc_html($current_browser); ?></strong></p>
			<p>Platform: <strong><?php echo esc_html($platform); ?></strong></p>
			<p>Internet service provider: <strong><?php echo esc_html($host); ?></strong></p>
			<?php if($is_vpn_or_proxy): ?>
			<p><strong>[WARNING]</strong> The user is behind a Proxy or VPN</p>
			<?php endif; ?>
			<p class="text-center">Monitor Login.</p>
		</div>
	</div>
</body>
</html>
<?php
return ob_get_clean();
	}

	private function get_plug_tmpl($status, $blogname, $plugin, $username, $remote_addr, $current_browser, $platform, $host, $is_vpn_or_proxy)
	{
ob_start();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<style>
.body{
	background: #f0f0f1;
	color: #718096;
	width: 100%;
	text-align: center;
}
.container{
	width: 100%;
}
.data{
	width: 570px;
	margin: 0 auto;
	background-color: #dde5ed;
	padding: 10px 20px;
	margin-top: 20px;
}
.text-center{
	text-align: center;
}
@media(max-width: 480px){
	.data{
		width: 100%;
	}
}
</style>
</head>
<body>
	<div class="container">
		<div class="data">
			<p>The Plugin <strong><?php echo esc_html($plugin); ?></strong> has been <strong><?php echo esc_html($status); ?></strong> on your wordpress website: <strong><?php echo esc_html($blogname); ?></strong></p>
			<p>By the User: <strong><?php echo esc_html($username); ?></strong></p>
			<p>From the IP: <strong><?php echo esc_html($remote_addr); ?></strong></p>
			<p>Browser: <strong><?php echo esc_html($current_browser); ?></strong></p>
			<p>Platform: <strong><?php echo esc_html($platform); ?></strong></p>
			<p>Internet service provider: <strong><?php echo esc_html($host); ?></strong></p>
			<?php if($is_vpn_or_proxy): ?>
			<p><strong>[WARNING]</strong> The user is behind a Proxy or VPN</p>
			<?php endif; ?>
			<p class="text-center">Monitor Login.</p>
		</div>
	</div>
</body>
</html>
<?php
return ob_get_clean();		
	}

	private function get_theme_tmpl($blogname, $new_name, $old_name, $username, $remote_addr, $current_browser, $platform, $host, $is_vpn_or_proxy)
	{
ob_start();
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<style>
.body{
	background: #f0f0f1;
	color: #718096;
	width: 100%;
	text-align: center;
}
.container{
	width: 100%;
}
.data{
	width: 570px;
	margin: 0 auto;
	background-color: #dde5ed;
	padding: 10px 20px;
	margin-top: 20px;
}
.text-center{
	text-align: center;
}
@media(max-width: 480px){
	.data{
		width: 100%;
	}
}
</style>
</head>
<body>
	<div class="container">
		<div class="data">
			<p>The active theme has switched from <strong><?php echo esc_html($old_name); ?></strong> to <strong><?php echo esc_html($new_name); ?></strong> on your wordpress website: <strong><?php echo esc_html($blogname); ?></strong></p>
			<p>By the User: <strong><?php echo esc_html($username); ?></strong></p>
			<p>From the IP: <strong><?php echo esc_html($remote_addr); ?></strong></p>
			<p>Browser: <strong><?php echo esc_html($current_browser); ?></strong></p>
			<p>Platform: <strong><?php echo esc_html($platform); ?></strong></p>
			<p>Internet service provider: <strong><?php echo esc_html($host); ?></strong></p>
			<?php if($is_vpn_or_proxy): ?>
			<p><strong>[WARNING]</strong> The user is behind a Proxy or VPN</p>
			<?php endif; ?>
			<p class="text-center">Monitor Login.</p>
		</div>
	</div>
</body>
</html>
<?php
return ob_get_clean();		
	}

	public function install()
	{
		update_option('monitorlogin_email', get_option('admin_email'));
		update_option('monitorlogin_plugs', 'yes');
		update_option('monitorlogin_themes', 'yes');
	}

	public function uninstall()
	{
		delete_option('monitorlogin_email');
		delete_option('monitorlogin_plugs');
		delete_option('monitorlogin_themes');
	}

	public function register_settings()
	{
		register_setting('monitorlogin_settings', 'monitorlogin_email');
		register_setting('monitorlogin_settings', 'monitorlogin_plugs');
		register_setting('monitorlogin_settings', 'monitorlogin_themes');
	}

	public function register_admin_menu()
	{
		add_submenu_page(
			'options-general.php',
			'Monitor Login',
			'Monitor Login',
			'manage_options',
			'monitor-login',
			array($this, 'admin_callback')
		);
	}

	public function admin_callback()
	{
		$monitoremail = get_option('monitorlogin_email');
		$monitorplugs = get_option('monitorlogin_plugs');
		$monitorthemes = get_option('monitorlogin_themes');
		?>
		<div class="wrap">
			<h2><?php echo esc_html(get_admin_page_title()); ?></h2>
			<form method="post" action="options.php">
				<?php 
				settings_fields('monitorlogin_settings');
				?>
				<table class="form-table">
					<tbody>
						<tr>
							<td style="width: 250px;">
								<p>Email for login alerts notifications</p>
							</td>	
							<td>
								<input type="text" name="monitorlogin_email" value="<?php echo esc_html($monitoremail); ?>">		
							</td>
						</tr>
						<tr>
							<td style="width: 250px;">
								<p>Plugin activation/deactivation/deleted notifications</p>		
							</td>
							<td>
								<select name="monitorlogin_plugs">
									<option value="no" <?php if($monitorplugs == 'no'){echo 'selected="selected"';} ?>>No</option>
									<option value="yes" <?php if($monitorplugs == 'yes'){echo 'selected="selected"';} ?>>Yes</option>
								</select>		
							</td>
						</tr>
						<tr>
							<td style="width: 250px;">
								<p>Themes switching notifications</p>		
							</td>
							<td>
								<select name="monitorlogin_themes">
								<option value="no" <?php if($monitorthemes == 'no'){echo 'selected="selected"';} ?>>No</option>
								<option value="yes" <?php if($monitorthemes == 'yes'){echo 'selected="selected"';} ?>>Yes</option>
							</select>		
							</td>
						</tr>
					</tbody>
				</table>
				<?php submit_button('save'); ?>
			</form>
		</div>
		<?php
	}

}