<?php
/**
 * Loads the library without WordPress or composer.
 *
 * Stands in for the WordPress functions the library calls, keeping hooks,
 * options and transients in WP_Stubs. Also loads fixtures/old-copy, which is
 * src/ at ca7290d (the last copy in the Polevaultweb\WPOAuth2 namespace)
 * unchanged, as another plugin on the same site would bundle it.
 *
 * Run with PHPUnit 9: phpunit -c tests/phpunit.xml
 */

spl_autoload_register(
	function ( $class ) {
		$prefix = 'Polevaultweb\\WPOAuth2\\V3\\';
		if ( 0 !== strpos( $class, $prefix ) ) {
			return;
		}

		$file = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
		if ( file_exists( $file ) ) {
			require $file;
		}
	}
);

foreach ( array( 'AccessTokenInterface', 'AbstractAccessToken', 'AccessToken', 'TokenManager', 'AdminHandler', 'WPOAuth2' ) as $old_class ) {
	require_once __DIR__ . '/fixtures/old-copy/' . $old_class . '.php';
}

class WP_Stubs {

	public static $filters = array();

	public static $options = array();

	public static $site_options = array();

	public static $site_transients = array();

	public static $remote_responses = array();

	public static $remote_requests = array();

	public static $valid_nonces = true;

	public static function reset() {
		self::$filters          = array();
		self::$options          = array();
		self::$site_options     = array();
		self::$site_transients  = array();
		self::$remote_responses = array();
		self::$remote_requests  = array();
		self::$valid_nonces     = true;
	}
}

function add_filter( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
	WP_Stubs::$filters[ $hook_name ][ $priority ][] = array( $callback, $accepted_args );

	return true;
}

function add_action( $hook_name, $callback, $priority = 10, $accepted_args = 1 ) {
	return add_filter( $hook_name, $callback, $priority, $accepted_args );
}

function has_action( $hook_name ) {
	return ! empty( WP_Stubs::$filters[ $hook_name ] );
}

function apply_filters( $hook_name, $value ) {
	$args = array_slice( func_get_args(), 2 );
	if ( empty( WP_Stubs::$filters[ $hook_name ] ) ) {
		return $value;
	}

	$callbacks = WP_Stubs::$filters[ $hook_name ];
	ksort( $callbacks );
	foreach ( $callbacks as $priority_callbacks ) {
		foreach ( $priority_callbacks as $callback ) {
			$value = call_user_func_array( $callback[0], array_slice( array_merge( array( $value ), $args ), 0, $callback[1] ) );
		}
	}

	return $value;
}

function do_action( $hook_name ) {
	$args = array_slice( func_get_args(), 1 );
	if ( empty( WP_Stubs::$filters[ $hook_name ] ) ) {
		return;
	}

	$callbacks = WP_Stubs::$filters[ $hook_name ];
	ksort( $callbacks );
	foreach ( $callbacks as $priority_callbacks ) {
		foreach ( $priority_callbacks as $callback ) {
			call_user_func_array( $callback[0], array_slice( $args, 0, $callback[1] ) );
		}
	}
}

function get_option( $option, $default_value = false ) {
	return array_key_exists( $option, WP_Stubs::$options ) ? WP_Stubs::$options[ $option ] : $default_value;
}

function update_option( $option, $value ) {
	WP_Stubs::$options[ $option ] = $value;

	return true;
}

function get_site_option( $option, $default_value = false ) {
	return array_key_exists( $option, WP_Stubs::$site_options ) ? WP_Stubs::$site_options[ $option ] : $default_value;
}

function update_site_option( $option, $value ) {
	WP_Stubs::$site_options[ $option ] = $value;

	return true;
}

function get_site_transient( $transient ) {
	return array_key_exists( $transient, WP_Stubs::$site_transients ) ? WP_Stubs::$site_transients[ $transient ] : false;
}

function set_site_transient( $transient, $value, $expiration = 0 ) {
	WP_Stubs::$site_transients[ $transient ] = $value;

	return true;
}

function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) {
	return bin2hex( random_bytes( 8 ) );
}

function add_query_arg( $args, $url ) {
	$parts = explode( '?', $url, 2 );
	$query = array();
	if ( isset( $parts[1] ) ) {
		parse_str( $parts[1], $query );
	}

	return $parts[0] . '?' . http_build_query( array_merge( $query, $args ), '', '&' );
}

function wp_nonce_url( $actionurl, $action = -1, $name = '_wpnonce' ) {
	return add_query_arg( array( $name => 'nonce-' . $action ), $actionurl );
}

function check_admin_referer( $action = -1, $query_arg = '_wpnonce' ) {
	if ( ! WP_Stubs::$valid_nonces ) {
		throw new RuntimeException( 'Nonce check failed for ' . $action );
	}

	return 1;
}

function wp_remote_get( $url, $args = array() ) {
	WP_Stubs::$remote_requests[] = $url;

	return array( 'body' => array_shift( WP_Stubs::$remote_responses ) );
}

function wp_remote_retrieve_body( $response ) {
	return $response['body'];
}

function is_wp_error( $thing ) {
	return false;
}

function __( $text, $domain = 'default' ) {
	return $text;
}

function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}

require __DIR__ . '/TestTokens.php';
require __DIR__ . '/TestAdminHandler.php';
require __DIR__ . '/WPOAuth2TestCase.php';
