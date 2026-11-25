<?php

namespace Polevaultweb\WPOAuth2\V3;

/**
 * Connects a WordPress plugin to a service through the OAuth proxy server.
 *
 * Each plugin gets its own instance, named by the instance key it passes to
 * instance(), with its own token class, login keys and filters, so two plugins
 * that bundle this library can run on the same site.
 *
 * The namespace carries the API version (V3). Releases before it used
 * Polevaultweb\WPOAuth2, whose WPOAuth2 was a single instance shared by every
 * plugin. A plugin that still bundles one of those copies defines those
 * classes, never these, so it can't take over this copy's instances. A change
 * that breaks this API needs a new namespace, because every plugin on a site
 * that bundles V3 runs whichever V3 copy loaded first.
 */
class WPOAuth2 {

	/**
	 * Instance key used when instance() is given neither a key nor a token class.
	 */
	const DEFAULT_INSTANCE = 'default';

	/**
	 * Query arg on callback, notice and disconnect URLs saying which instance they're for.
	 */
	const INSTANCE_QUERY_ARG = 'wp-oauth2-instance';

	/**
	 * Prefix of the filters, and of the site transient holding an instance's login keys.
	 */
	const FILTER_PREFIX = 'pvw_wp_oauth2_';

	const LOGIN_KEY_TRANSIENT_PREFIX = 'wp-oauth2-key-';

	/**
	 * @var WPOAuth2[] Keyed by instance key
	 */
	private static $instances = array();

	/**
	 * @var string
	 */
	protected $instance_key = self::DEFAULT_INSTANCE;

	/**
	 * @var string
	 */
	protected $oauth_proxy_url;

	/**
	 * @var TokenManager
	 */
	public $token_manager;

	/**
	 * Get the instance for a plugin, creating it the first time.
	 *
	 * @param string      $oauth_proxy_url
	 * @param null|string $token_class  Class that stores the plugin's tokens, implementing AccessTokenInterface
	 * @param null|string $instance_key Names the plugin's instance, eg. its slug. Defaults to the token class
	 *
	 * @return WPOAuth2 Instance
	 */
	public static function instance( $oauth_proxy_url, $token_class = null, $instance_key = null ) {
		if ( empty( $instance_key ) ) {
			$instance_key = empty( $token_class ) ? self::DEFAULT_INSTANCE : $token_class;
		}
		$instance_key = self::sanitize_instance_key( $instance_key );

		if ( ! isset( self::$instances[ $instance_key ] ) ) {
			$instance               = new WPOAuth2();
			$instance->instance_key = $instance_key;
			$instance->init( $oauth_proxy_url, $token_class );

			self::$instances[ $instance_key ] = $instance;
		}

		return self::$instances[ $instance_key ];
	}

	/**
	 * Make an instance key safe for hook, transient and query arg names.
	 *
	 * @param string $instance_key
	 *
	 * @return string Lower case letters, digits, underscores and hyphens
	 */
	public static function sanitize_instance_key( $instance_key ) {
		$instance_key = strtolower( preg_replace( '/[^A-Za-z0-9_\-]+/', '_', (string) $instance_key ) );
		$instance_key = trim( $instance_key, '_-' );

		if ( '' === $instance_key ) {
			return self::DEFAULT_INSTANCE;
		}

		if ( strlen( $instance_key ) > 64 ) {
			// Keep transient names inside the options table's limit
			return md5( $instance_key );
		}

		return $instance_key;
	}

	/**
	 * Name of a filter that only runs for one instance.
	 *
	 * @param string $instance_key
	 * @param string $hook Eg. 'redirect_url'
	 *
	 * @return string Eg. 'pvw_wp_oauth2_my_plugin_redirect_url'
	 */
	public static function filter_name( $instance_key, $hook ) {
		return self::FILTER_PREFIX . $instance_key . '_' . $hook;
	}

	/**
	 * Name of the site transient that holds an instance's login keys, one per provider.
	 *
	 * @param string $instance_key
	 *
	 * @return string
	 */
	public static function login_key_transient( $instance_key ) {
		return self::LOGIN_KEY_TRANSIENT_PREFIX . $instance_key;
	}

	/**
	 * @param string      $oauth_proxy_url
	 * @param null|string $token_class
	 */
	public function init( $oauth_proxy_url, $token_class = null ) {
		$this->oauth_proxy_url = $oauth_proxy_url;

		$this->token_manager = new TokenManager( $token_class );
	}

	/**
	 * @return string
	 */
	public function get_instance_key() {
		return $this->instance_key;
	}

	/**
	 * @return string
	 */
	public function get_oauth_proxy_url() {
		return $this->oauth_proxy_url;
	}

	/**
	 * Name of a filter that only runs for this instance.
	 *
	 * @param string $hook Eg. 'redirect_url'
	 *
	 * @return string
	 */
	public function get_filter_name( $hook ) {
		return self::filter_name( $this->instance_key, $hook );
	}

	/**
	 * Register the admin hooks for the plugin.
	 *
	 * @param string $redirect_url
	 *
	 * @return AdminHandler
	 */
	public function register_admin_handler( $redirect_url ) {
		$admin_handler = new AdminHandler( $this->token_manager, $redirect_url, $this->get_method(), $this->instance_key );
		$admin_handler->init();

		return $admin_handler;
	}

	/**
	 * Get the URL to the proxy server to redirect to, to start the auth process.
	 *
	 * @param string $provider
	 * @param string $client_id
	 * @param string $callback_url
	 * @param array  $args
	 *
	 * @return string
	 */
	public function get_authorize_url( $provider, $client_id, $callback_url, $args = array() ) {
		$params = array(
			'redirect_uri' => $this->add_instance_arg( $callback_url ),
			'client_id'    => $client_id,
			'key'          => $this->generate_key( $provider ),
			'method'       => $this->get_method(),
		);

		if ( ! empty( $args ) ) {
			$params['args'] = base64_encode( serialize( $args ) );
		}

		$url = $this->oauth_proxy_url . '?' . http_build_query( $params, '', '&' );

		return $url;
	}

	/**
	 * Send a refresh token to the proxy server for a client and get a new access token back.
	 *
	 * @param string      $client_id
	 * @param string      $provider
	 *
	 * @return bool|string
	 */
	public function refresh_access_token( $client_id, $provider ) {
		$refresh_token = $this->token_manager->get_refresh_token( $provider );

		$params = array(
			'client_id'     => $client_id,
			'refresh_token' => $refresh_token,
		);

		$url = $this->oauth_proxy_url . '/refresh?' . http_build_query( $params, '', '&' );

		$request = wp_remote_get( $url );

		if ( is_wp_error( $request ) ) {
			return false; // Bail early
		}

		$body = wp_remote_retrieve_body( $request );

		$data = json_decode( $body, true );
		if ( ! $data || ! isset( $data['token'] ) ) {
			return false;
		}

		$expires = isset( $data['expires'] ) ? $data['expires'] : null;

		$this->token_manager->set_access_token( $provider, $data['token'], $refresh_token, $expires );

		return $data['token'];
	}

	public function get_method() {
		$methods = openssl_get_cipher_methods();

		return $methods[0];
	}

	/**
	 * The key the proxy encrypts the token with, saved when the authorize URL was made.
	 *
	 * @param string $provider
	 *
	 * @return string|false
	 */
	public function get_login_key( $provider ) {
		$keys = get_site_transient( self::login_key_transient( $this->instance_key ) );

		return isset( $keys[ $provider ] ) ? $keys[ $provider ] : false;
	}

	/**
	 * @param string $provider
	 *
	 * @return string
	 */
	protected function generate_key( $provider ) {
		$transient = self::login_key_transient( $this->instance_key );
		$keys      = get_site_transient( $transient );

		if ( ! is_array( $keys ) ) {
			$keys = array();
		}

		$key = wp_generate_password();

		$keys[ $provider ] = $key;

		set_site_transient( $transient, $keys );

		return $key;
	}

	/**
	 * @param string $url
	 *
	 * @return string The URL, saying it's for this instance
	 */
	protected function add_instance_arg( $url ) {
		return add_query_arg( array( self::INSTANCE_QUERY_ARG => $this->instance_key ), $url );
	}

	public function get_disconnect_url( $provider, $url ) {
		$args = array(
			'wp-oauth2'              => $provider,
			'action'                 => 'disconnect',
			self::INSTANCE_QUERY_ARG => $this->instance_key,
		);

		return wp_nonce_url( add_query_arg( $args, $url ), 'wp-oauth-disconnect' );
	}

	public function disconnect( $provider ) {
		$this->token_manager->remove_access_token( $provider );
	}

	public function is_authorized( $provider ) {
		$token = $this->token_manager->get_access_token( $provider );

		return (bool) $token;
	}

	/**
	 * Protected constructor to prevent creating a new instance of the
	 * class via the `new` operator from outside of this class.
	 */
	protected function __construct() {
	}

	/**
	 * Instances are only created by instance(), so they can't be cloned
	 */
	protected function __clone() {
	}

	/**
	 * Instances are only created by instance(), so they can't be unserialized
	 */
	public function __wakeup() {
	}
}
