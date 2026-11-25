<?php
/**
 * AdminHandler reading the request from Test_Admin_Handler::$query instead of
 * filter_input(), which only sees the real request, and recording the URL it
 * redirects to instead of exiting.
 */
class Test_Admin_Handler extends Polevaultweb\WPOAuth2\V3\AdminHandler {

	/** @var array The request's query args */
	public static $query = array();

	/** @var string|null */
	public $redirected_to;

	protected function get_query_arg( $name, $filter = FILTER_DEFAULT ) {
		if ( ! isset( self::$query[ $name ] ) ) {
			return null;
		}

		return filter_var( self::$query[ $name ], $filter );
	}

	protected function do_redirect( $url ) {
		$this->redirected_to = $url;
	}

	/**
	 * A handler for a WPOAuth2 instance, as register_admin_handler() makes.
	 *
	 * @param Polevaultweb\WPOAuth2\V3\WPOAuth2 $wpoauth
	 * @param string                            $redirect
	 *
	 * @return Test_Admin_Handler
	 */
	public static function for_instance( $wpoauth, $redirect ) {
		return new self( $wpoauth->token_manager, $redirect, $wpoauth->get_method(), $wpoauth->get_instance_key() );
	}
}
