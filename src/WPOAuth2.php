<?php

namespace Polevaultweb\WPOAuth2;

class WPOAuth2 {

	public static function get_disconnect_url( $provider, $url ) {
		$url = add_query_arg( array( 'wp-oauth2' => $provider, 'action' => 'disconnect' ), $url );

		return $url;
	}

	public static function disconnect( $provider ) {
		$token = new AccessToken( $provider );
		$token->delete();
	}

	public static function get_access_token( $provider ) {
		$token = new AccessToken( $provider );

		return $token->get();
	}

	public static function set_access_token( $provider, $token ) {
		$token = new AccessToken( $provider, $token );
		$token->save();
	}

	public static function is_authorized( $provider ) {
		$token = self::get_access_token( $provider );

		return (bool) $token;
	}
}