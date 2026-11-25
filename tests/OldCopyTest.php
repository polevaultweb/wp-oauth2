<?php

use Polevaultweb\WPOAuth2\V3\WPOAuth2;

/**
 * Another plugin on the site bundles a copy from before V3, which defines
 * Polevaultweb\WPOAuth2\WPOAuth2 as one instance shared by every plugin. It
 * may load first, as Intagrate Pro does before Intagrate Lite. It can't take
 * over the V3 instances, and neither copy overwrites the other's login key.
 */
class OldCopyTest extends WPOAuth2_TestCase {

	const LITE_PAGE = 'https://example.test/wp-admin/options-general.php?page=lite';

	public function test_old_copy_loaded_first_does_not_become_the_v3_instance() {
		$old  = Polevaultweb\WPOAuth2\WPOAuth2::instance( self::PROXY, Test_Old_Copy_Token::class );
		$lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );

		$old->token_manager->set_access_token( self::PROVIDER, 'old-token' );
		$lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );

		$this->assertNotInstanceOf( Polevaultweb\WPOAuth2\WPOAuth2::class, $lite );
		$this->assertSame( 'old-token', $old->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertSame( 'lite-token', $lite->token_manager->get_access_token( self::PROVIDER ) );
	}

	public function test_old_copy_keeps_its_singleton() {
		$old = Polevaultweb\WPOAuth2\WPOAuth2::instance( self::PROXY, Test_Old_Copy_Token::class );
		WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );

		$this->assertSame( $old, Polevaultweb\WPOAuth2\WPOAuth2::instance( self::PROXY, Test_Lite_Token::class ) );
	}

	public function test_login_keys_are_kept_separate_from_the_old_copy() {
		$old  = Polevaultweb\WPOAuth2\WPOAuth2::instance( self::PROXY, Test_Old_Copy_Token::class );
		$lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );

		$old_key  = $this->query( $old->get_authorize_url( self::PROVIDER, 'client', 'https://example.test/wp-admin/post.php' ) )['key'];
		$lite_key = $this->query( $lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE ) )['key'];
		// The old plugin shows its login link again while Lite is mid-login
		$old_key = $this->query( $old->get_authorize_url( self::PROVIDER, 'client', 'https://example.test/wp-admin/post.php' ) )['key'];

		$this->assertSame( array( self::PROVIDER => $old_key ), WP_Stubs::$site_transients['wp-oauth2-key'] );
		$this->assertSame( $lite_key, $lite->get_login_key( self::PROVIDER ) );
	}

	public function test_v3_login_completes_after_the_old_copy_made_a_key() {
		$old     = Polevaultweb\WPOAuth2\WPOAuth2::instance( self::PROXY, Test_Old_Copy_Token::class );
		$lite    = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );
		$handler = Test_Admin_Handler::for_instance( $lite, self::LITE_PAGE );

		$login = $lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE );
		$old->get_authorize_url( self::PROVIDER, 'client', 'https://example.test/wp-admin/post.php' );
		$this->visit( $this->proxy_callback( $login, 'lite-token' ) );
		$handler->handle_redirect();

		$this->assertSame( 'lite-token', WP_Stubs::$options['lite_token']['token'] );
		$this->assertFalse( get_option( 'old_copy_token' ) );
	}
}
