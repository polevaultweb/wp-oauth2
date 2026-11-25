<?php
/**
 * Token classes for two plugins on one site, like Intagrate Pro and Lite,
 * each storing its token in its own option.
 */

abstract class Test_Option_Token extends Polevaultweb\WPOAuth2\V3\AbstractAccessToken {

	const OPTION = '';

	public function save() {
		update_option(
			static::OPTION,
			array(
				'token'   => $this->token,
				'expires' => $this->expires,
				'values'  => $this->values,
			)
		);
	}

	public function delete() {
		update_option( static::OPTION, array() );
	}

	public function get_token() {
		$data = get_option( static::OPTION );

		return empty( $data['token'] ) ? false : $data['token'];
	}

	public function get_refresh_token() {
		return $this->get_token();
	}
}

class Test_Pro_Token extends Test_Option_Token {

	const OPTION = 'pro_token';
}

class Test_Lite_Token extends Test_Option_Token {

	const OPTION = 'lite_token';
}

/**
 * Token class of a plugin that bundles the old copy (Polevaultweb\WPOAuth2).
 */
class Test_Old_Copy_Token extends Polevaultweb\WPOAuth2\AbstractAccessToken {

	public function save() {
		update_option( 'old_copy_token', $this->token );
	}

	public function delete() {
		update_option( 'old_copy_token', '' );
	}

	public function get_token() {
		return get_option( 'old_copy_token' );
	}

	public function get_refresh_token() {
		return $this->get_token();
	}
}
