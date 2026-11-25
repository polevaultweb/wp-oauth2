<?php

namespace Polevaultweb\WPOAuth2\V3;

class AdminHandler {

	/**
	 * @var string
	 */
	protected $redirect;

	/**
	 * @var TokenManager
	 */
	protected $token_manager;

	/**
	 * @var string
	 */
	protected $openssl_encrypt_method;

	/**
	 * @var string
	 */
	protected $instance_key;

	/**
	 * Admin_Handler constructor.
	 *
	 * @param TokenManager $token_manager
	 * @param string       $redirect
	 * @param string       $openssl_encrypt_method
	 * @param string       $instance_key Key of the WPOAuth2 instance this handles callbacks for
	 */
	public function __construct( $token_manager, $redirect, $openssl_encrypt_method, $instance_key = WPOAuth2::DEFAULT_INSTANCE ) {
		$this->token_manager          = $token_manager;
		$this->redirect               = $redirect;
		$this->openssl_encrypt_method = $openssl_encrypt_method;
		$this->instance_key           = $instance_key;
	}

	public function init() {
		add_action( 'admin_init', array( $this, 'handle_redirect' ) );
		add_action( 'admin_init', array( $this, 'handle_disconnect' ) );
		add_action( 'admin_init', array( $this, 'handle_render_notice' ) );
	}

	public function handle_render_notice() {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( ! $this->is_callback_page() || ! $this->is_for_this_instance() ) {
			return;
		}

		$notice = $this->get_query_arg( 'notice' );
		if ( empty( $notice ) ) {
			return;
		}

		if ( ! check_admin_referer( 'wp-oauth-' . $notice ) ) {
			return;
		}

		add_action( 'admin_notices', array( $this, 'render_' . $notice . '_notice' ) );
	}

	public function handle_disconnect() {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( ! $this->is_callback_page() || ! $this->is_for_this_instance() ) {
			return;
		}

		$provider = $this->get_query_arg( 'wp-oauth2' );
		if ( empty( $provider ) ) {
			return;
		}

		$action = $this->get_query_arg( 'action' );
		if ( empty( $action ) || 'disconnect' !== $action ) {
			return;
		}

		if ( ! check_admin_referer( 'wp-oauth-disconnect' ) ) {
			return;
		}

		$this->token_manager->remove_access_token( $provider );

		$this->redirect( 'disconnection', $provider );
	}

	/**
	 * @param null|string $notice
	 * @param string      $provider
	 * @param array       $args
	 */
	protected function redirect( $notice = null, $provider = '', $args = array() ) {
		$args = array_merge( array(
			'notice'                     => $notice,
			'wp-oauth2'                  => $provider,
			WPOAuth2::INSTANCE_QUERY_ARG => $this->instance_key,
		), $args );

		$url = add_query_arg( $args, $this->apply_filters( 'redirect_url', $this->redirect ) );

		$url = wp_nonce_url( $url, 'wp-oauth-' . $notice );

		$this->do_redirect( $url );
	}

	/**
	 * @param string $url
	 */
	protected function do_redirect( $url ) {
		wp_redirect( $url );
		exit;
	}

	protected function is_callback_page() {
		$parts = parse_url( $this->apply_filters( 'is_callback_page_redirect_url', $this->redirect ) );

		global $pagenow;
		if ( ! isset( $pagenow ) ) {
			return false;
		}
		if ( $pagenow !== basename( $parts['path'] ) ) {
			return false;
		}

		if ( ! isset( $parts['query'] ) ) {
			return false;
		}

		parse_str( $parts['query'], $query );
		foreach ( $query as $key => $value ) {
			$param = $this->get_query_arg( $key );
			if ( empty( $param ) ) {
				return false;
			}

			if ( $param != $value ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Is the request for this instance, rather than another plugin's?
	 *
	 * URLs made before instances had their own keys don't say, so they are
	 * handled by every instance whose callback page they're on, as they were.
	 *
	 * @return bool
	 */
	protected function is_for_this_instance() {
		$instance_key = $this->get_query_arg( WPOAuth2::INSTANCE_QUERY_ARG );

		return empty( $instance_key ) || $instance_key === $this->instance_key;
	}

	public function handle_redirect() {
		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			return;
		}

		if ( ! $this->is_callback_page() || ! $this->is_for_this_instance() ) {
			return;
		}

		$provider = $this->get_query_arg( 'wp-oauth2' );
		if ( empty( $provider ) ) {
			return;
		}

		$action = $this->get_query_arg( 'action' );
		if ( empty( $action ) || 'connect' !== $action ) {
			return;
		}

		$error = $this->get_query_arg( 'error' );
		if ( $error ) {
			$error_args = array( 'error' => $error );
			// Show error notice
			$error_desp = $this->get_query_arg( 'error_description' );

			if ( $error_desp ) {
				$error_args['error_description'] = $error_desp;
			}

			$this->redirect( 'error', $provider, $error_args );
			return;
		}

		$token = $this->get_query_arg( 'token' );
		$iv    = $this->get_query_arg( 'iv' );
		if ( empty( $token ) || empty( $iv ) ) {
			$this->redirect( 'error' );
			return;
		}

		$method = $this->openssl_encrypt_method;
		$keys   = get_site_transient( WPOAuth2::login_key_transient( $this->instance_key ) );
		if ( ! isset( $keys[ $provider ] ) ) {
			$this->redirect( 'error', $provider );
			return;
		}
		$key   = $keys[ $provider ];
		$token = openssl_decrypt( $token, $method, $key, 0, urldecode( $iv ) );
		if ( empty( $token ) ) {
			$this->redirect( 'error', $provider );
			return;
		}

		$refresh_token_data = $this->get_query_arg( 'refresh_token' );
		$refresh_token      = null;
		if ( $refresh_token_data ) {
			$refresh_token = openssl_decrypt( $refresh_token_data, $method, $key, 0, urldecode( $iv ) );
		}

		$values_data = $this->get_query_arg( 'values' );
		$values      = null;
		if ( $values_data ) {
			$values = openssl_decrypt( $values_data, $method, $key, 0, urldecode( $iv ) );
		}

		$expires = $this->get_query_arg( 'expires', FILTER_VALIDATE_INT );

		$this->token_manager->set_access_token( $provider, $token, $refresh_token, $expires, $values );

		$this->redirect( 'connection', $provider );
	}

	/**
	 * Read a query arg from the request.
	 *
	 * @param string $name
	 * @param int    $filter
	 *
	 * @return mixed
	 */
	protected function get_query_arg( $name, $filter = FILTER_DEFAULT ) {
		return filter_input( INPUT_GET, $name, $filter );
	}

	/**
	 * Apply a filter for every instance, then the filter for this instance only.
	 *
	 * Both get the instance key as their last argument. 'pvw_wp_oauth2_{$hook}'
	 * runs for every plugin's instance, as it did before instances had their own
	 * filters, so a plugin should hook 'pvw_wp_oauth2_{$instance_key}_{$hook}'.
	 *
	 * @param string $hook  Eg. 'redirect_url'
	 * @param mixed  $value
	 * @param array  $args  Arguments after the value
	 *
	 * @return mixed
	 */
	protected function apply_filters( $hook, $value, $args = array() ) {
		$args[] = $this->instance_key;

		$value = call_user_func_array( 'apply_filters', array_merge( array( WPOAuth2::FILTER_PREFIX . $hook, $value ), $args ) );

		return call_user_func_array( 'apply_filters', array_merge( array( WPOAuth2::filter_name( $this->instance_key, $hook ), $value ), $args ) );
	}

	protected function get_provider_display_name() {
		$provider = $this->get_query_arg( 'wp-oauth2' );
		$name = ucwords( str_replace( array( '_', '-' ), ' ', $provider ) );

		return $this->apply_filters( 'provider_display_name', $name, array( $provider ) );
	}

	public function render_error_notice() {
		$provider = $this->get_provider_display_name();

		$error_description = $this->get_query_arg( 'error_description' );
		$message           = $error_description ? $error_description : __( 'An unknown error occurred.' );
		$message           = $this->apply_filters( 'error_notice_message', $message, array( $provider ) );
		$class             = $this->apply_filters( 'error_notice_class', 'error', array( $provider ) );

		printf( '<div class="' . $class . '"><p><strong>' . $provider . ' %s</strong> &mdash; %s</p></div>', __( 'Connection Error' ), esc_html( $message ) );
	}

	public function render_connection_notice() {
		$provider = $this->get_provider_display_name();

		$message = sprintf( __( 'You have successfully connected with your %s account.' ), $provider );
		$class = $this->apply_filters( 'connection_notice_class', 'updated' );
		printf( '<div class="' . $class . '"><p><strong>' . $provider . ' %s</strong> &mdash; %s</p></div>', __( 'Connected' ), $message );
	}

	public function render_disconnection_notice() {
		$provider = $this->get_provider_display_name();

		$message = sprintf( __( 'You have successfully disconnected your %s account.' ), $provider );
		$class = $this->apply_filters( 'disconnection_notice_class', 'updated' );
		printf( '<div class="' . $class . '"><p><strong>' . $provider . ' %s</strong> &mdash; %s</p></div>', __( 'Disconnected' ), $message );
	}
}
