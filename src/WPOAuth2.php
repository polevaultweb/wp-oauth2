<?php

namespace Polevaultweb\WPOAuth2;

class WPOAuth2 {

	/**
	 * @var WPOAuth2
	 */
	private static $instance;

	/**
	 * @var string
	 */
	protected $oauth_proxy_url;

	/**
	 * @var TokenManager
	 */
	public $token_manager;

	/**
	 * @param string $oauth_proxy_url
	 *
	 * @return WPOAuth2 Instance
	 */
	public static function instance( $oauth_proxy_url ) {
		if ( ! isset( self::$instance ) && ! ( self::$instance instanceof WPOAuth2 ) ) {
			self::$instance = new WPOAuth2();
			self::$instance->init( $oauth_proxy_url );
		}

		return self::$instance;
	}

	/**
	 * @param string $oauth_proxy_url
	 */
	public function init( $oauth_proxy_url ) {
		$this->oauth_proxy_url = $oauth_proxy_url;

		$this->token_manager = new TokenManager();
	}

	/**
	 * Register the admin hooks for the plugin.
	 *
	 * @param string $redirect_url
	 */
	public function register_admin_handler( $redirect_url ) {
		$admin_handler = new AdminHandler( $this->token_manager, $redirect_url, $this->get_method() );
		$admin_handler->init();
	}

	/**
	 * Get the URL to the proxy server to redirect to, to start the auth process.
	 *
	 * @param string  $client_id
	 * @param  string $callback_url
	 * @param array   $args
	 *
	 * @return string
	 */
	public function get_authorize_url( $client_id, $callback_url, $args = array() ) {
		$params = array(
			'redirect_uri' => $callback_url,
			'client_id'    => $client_id,
			'key'          => $this->get_key(),
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
	 * @param string $client_id
	 * @param string $provider
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

		$this->token_manager->set_access_token( $provider, $data['token'], $refresh_token );

		return $data['token'];
	}

	public function get_method() {
		$methods = openssl_get_cipher_methods();

		return $methods[0];
	}

	protected function get_key() {
		$key = wp_generate_password();

		set_site_transient( 'wp-oauth2-key', $key );

		return $key;
	}

	public function get_disconnect_url( $provider, $url ) {
		$url = add_query_arg( array( 'wp-oauth2' => $provider, 'action' => 'disconnect' ), $url );

		return $url;
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
	 * As this class is a singleton it should not be clone-able
	 */
	protected function __clone() {
	}

	/**
	 * As this class is a singleton it should not be able to be unserialized
	 */
	protected function __wakeup() {
	}
}