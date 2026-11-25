<?php

use Polevaultweb\WPOAuth2\V3\WPOAuth2;

/**
 * Two plugins on one site bundle this library and log in to the same provider
 * through the same proxy, like Intagrate Pro and Intagrate Lite (GitHub
 * polevaultweb/intagrate#368). Each keeps its own token, login key, callback
 * handling and filters.
 */
class TwoPluginsTest extends WPOAuth2_TestCase {

	const PRO_PAGE = 'https://example.test/wp-admin/admin.php?page=pro';

	const LITE_PAGE = 'https://example.test/wp-admin/options-general.php?page=lite';

	/** @var WPOAuth2 */
	private $pro;

	/** @var WPOAuth2 */
	private $lite;

	protected function setUp(): void {
		parent::setUp();

		// Pro loads first, as plugins load alphabetically
		$this->pro  = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class, 'instagrate_pro' );
		$this->lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );
	}

	public function test_each_plugin_reads_and_saves_its_own_token() {
		$this->lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );
		$this->pro->token_manager->set_access_token( self::PROVIDER, 'pro-token' );

		$this->assertSame( 'pro-token', $this->pro->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertSame( 'lite-token', $this->lite->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertSame( 'pro-token', WP_Stubs::$options['pro_token']['token'] );
		$this->assertSame( 'lite-token', WP_Stubs::$options['lite_token']['token'] );
	}

	public function test_a_plugin_is_logged_out_when_only_the_other_has_a_token() {
		$this->pro->token_manager->set_access_token( self::PROVIDER, 'pro-token' );

		$this->assertTrue( $this->pro->is_authorized( self::PROVIDER ) );
		$this->assertFalse( $this->lite->is_authorized( self::PROVIDER ) );
	}

	public function test_lite_reads_its_own_token_when_it_registers_first() {
		$this->setUp_in_order( array( 'lite', 'pro' ) );

		$this->lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );

		$this->assertSame( 'lite-token', $this->lite->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertFalse( $this->pro->token_manager->get_access_token( self::PROVIDER ) );
	}

	public function test_login_keys_are_kept_separate() {
		$pro_key  = $this->query( $this->pro->get_authorize_url( self::PROVIDER, 'client', self::PRO_PAGE ) )['key'];
		$lite_key = $this->query( $this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE ) )['key'];

		$this->assertNotSame( $pro_key, $lite_key );
		$this->assertSame( $pro_key, $this->pro->get_login_key( self::PROVIDER ) );
		$this->assertSame( $lite_key, $this->lite->get_login_key( self::PROVIDER ) );
		$this->assertSame( array( self::PROVIDER => $pro_key ), WP_Stubs::$site_transients['wp-oauth2-key-instagrate_pro'] );
		$this->assertSame( array( self::PROVIDER => $lite_key ), WP_Stubs::$site_transients['wp-oauth2-key-intagrate_lite'] );
		$this->assertArrayNotHasKey( 'wp-oauth2-key', WP_Stubs::$site_transients, 'The key shared by old copies is left alone' );
	}

	public function test_callback_url_says_which_instance_it_is_for() {
		$redirect_uri = $this->query( $this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE ) )['redirect_uri'];

		$this->assertSame( array( 'page' => 'lite', WPOAuth2::INSTANCE_QUERY_ARG => 'intagrate_lite' ), $this->query( $redirect_uri ) );
	}

	/**
	 * Showing one plugin's login link while the other
	 * is mid-login used to overwrite the shared key, so the login failed.
	 */
	public function test_each_plugin_completes_its_login_when_the_other_started_one_since() {
		$pro_login  = $this->pro->get_authorize_url( self::PROVIDER, 'client', self::PRO_PAGE );
		$lite_login = $this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE );

		$this->handle_callback( $this->proxy_callback( $pro_login, 'pro-token', array( 'expires' => '1700000000' ) ) );
		$this->handle_callback( $this->proxy_callback( $lite_login, 'lite-token' ) );

		$this->assertSame( array( 'token' => 'pro-token', 'expires' => 1700000000, 'values' => null ), WP_Stubs::$options['pro_token'] );
		$this->assertSame( 'lite-token', WP_Stubs::$options['lite_token']['token'] );
	}

	public function test_callback_for_the_other_instance_on_a_shared_page_is_left_to_it() {
		$pro_handler  = Test_Admin_Handler::for_instance( $this->pro, self::LITE_PAGE );
		$lite_handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );

		$this->visit( $this->proxy_callback( $this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE ), 'lite-token' ) );
		$pro_handler->handle_redirect();
		$lite_handler->handle_redirect();

		$this->assertNull( $pro_handler->redirected_to );
		$this->assertArrayNotHasKey( 'pro_token', WP_Stubs::$options );
		$this->assertSame( 'lite-token', WP_Stubs::$options['lite_token']['token'] );

		$notice = $this->query( $lite_handler->redirected_to );
		$this->assertSame( 'connection', $notice['notice'] );
		$this->assertSame( 'intagrate_lite', $notice[ WPOAuth2::INSTANCE_QUERY_ARG ] );
	}

	/**
	 * A login started before the update has no instance in its callback URL, so
	 * the handler for the page takes it. Its key was saved by the old copy, so
	 * it fails with an error notice and the user logs in again.
	 */
	public function test_callback_without_an_instance_is_handled_by_the_page() {
		$handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );
		$login   = $this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE );

		$this->visit( str_replace( '&' . WPOAuth2::INSTANCE_QUERY_ARG . '=intagrate_lite', '', $this->proxy_callback( $login, 'lite-token' ) ) );
		$this->assertArrayNotHasKey( WPOAuth2::INSTANCE_QUERY_ARG, Test_Admin_Handler::$query );
		$handler->handle_redirect();

		$this->assertSame( 'lite-token', WP_Stubs::$options['lite_token']['token'] );
	}

	public function test_callback_with_a_key_from_the_other_instance_fails() {
		$handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );
		$login   = $this->pro->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE );
		$this->lite->get_authorize_url( self::PROVIDER, 'client', self::LITE_PAGE );

		$callback = $this->proxy_callback( $login, 'pro-token' );
		$this->visit( str_replace( 'instagrate_pro', 'intagrate_lite', $callback ) );
		$handler->handle_redirect();

		$this->assertArrayNotHasKey( 'lite_token', WP_Stubs::$options );
		$this->assertSame( 'error', $this->query( $handler->redirected_to )['notice'] );
	}

	public function test_disconnect_only_removes_that_plugins_token() {
		$this->pro->token_manager->set_access_token( self::PROVIDER, 'pro-token' );
		$this->lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );
		$pro_handler  = Test_Admin_Handler::for_instance( $this->pro, self::LITE_PAGE );
		$lite_handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );

		$this->visit( $this->lite->get_disconnect_url( self::PROVIDER, self::LITE_PAGE ) );
		$pro_handler->handle_disconnect();
		$lite_handler->handle_disconnect();

		$this->assertSame( 'pro-token', $this->pro->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertFalse( $this->lite->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertNull( $pro_handler->redirected_to );
		$this->assertSame( 'disconnection', $this->query( $lite_handler->redirected_to )['notice'] );
	}

	public function test_notice_is_only_shown_by_its_instance() {
		$pro_handler  = Test_Admin_Handler::for_instance( $this->pro, self::LITE_PAGE );
		$lite_handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );

		$this->visit( add_query_arg( array( 'notice' => 'connection', 'wp-oauth2' => self::PROVIDER, WPOAuth2::INSTANCE_QUERY_ARG => 'intagrate_lite' ), self::LITE_PAGE ) );
		$pro_handler->handle_render_notice();
		$lite_handler->handle_render_notice();

		$this->assertSame( array( array( array( $lite_handler, 'render_connection_notice' ), 1 ) ), WP_Stubs::$filters['admin_notices'][10] );
	}

	public function test_scoped_filters_only_run_for_their_instance() {
		add_filter(
			'pvw_wp_oauth2_instagrate_pro_provider_display_name',
			function () {
				return 'Pro Instagram';
			}
		);
		add_filter(
			'pvw_wp_oauth2_intagrate_lite_provider_display_name',
			function () {
				return 'Lite Instagram';
			}
		);
		$this->visit( add_query_arg( array( 'notice' => 'connection', 'wp-oauth2' => self::PROVIDER ), self::LITE_PAGE ) );

		$this->assertStringContainsString( '<strong>Pro Instagram Connected</strong>', $this->render( Test_Admin_Handler::for_instance( $this->pro, self::LITE_PAGE ) ) );
		$this->assertStringContainsString( '<strong>Lite Instagram Connected</strong>', $this->render( Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE ) ) );
	}

	public function test_unscoped_filters_run_for_every_instance_and_are_told_which() {
		$seen = array();
		add_filter(
			'pvw_wp_oauth2_provider_display_name',
			function ( $name, $provider, $instance_key ) use ( &$seen ) {
				$seen[] = array( $name, $provider, $instance_key );

				return $name;
			},
			10,
			3
		);
		// As an old plugin hooks it, with one argument
		add_filter(
			'pvw_wp_oauth2_provider_display_name',
			function () {
				return 'Instagram';
			}
		);
		$this->visit( add_query_arg( array( 'notice' => 'connection', 'wp-oauth2' => self::PROVIDER ), self::LITE_PAGE ) );

		$this->assertStringContainsString( '<strong>Instagram Connected</strong>', $this->render( Test_Admin_Handler::for_instance( $this->pro, self::LITE_PAGE ) ) );
		$this->assertStringContainsString( '<strong>Instagram Connected</strong>', $this->render( Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE ) ) );
		$this->assertSame(
			array(
				array( 'Instagram Facebook', self::PROVIDER, 'instagrate_pro' ),
				array( 'Instagram Facebook', self::PROVIDER, 'intagrate_lite' ),
			),
			$seen
		);
	}

	public function test_scoped_redirect_url_filter_only_changes_its_instances_redirect() {
		add_filter(
			'pvw_wp_oauth2_instagrate_pro_redirect_url',
			function ( $url ) {
				return add_query_arg( array( 'post' => 42 ), $url );
			}
		);
		$pro_handler  = Test_Admin_Handler::for_instance( $this->pro, self::PRO_PAGE );
		$lite_handler = Test_Admin_Handler::for_instance( $this->lite, self::LITE_PAGE );

		$this->visit( $this->pro->get_disconnect_url( self::PROVIDER, self::PRO_PAGE ) );
		$pro_handler->handle_disconnect();
		$this->visit( $this->lite->get_disconnect_url( self::PROVIDER, self::LITE_PAGE ) );
		$lite_handler->handle_disconnect();

		$this->assertSame( '42', $this->query( $pro_handler->redirected_to )['post'] );
		$this->assertArrayNotHasKey( 'post', $this->query( $lite_handler->redirected_to ) );
	}

	public function test_scoped_callback_page_filter_only_changes_its_instances_page() {
		add_filter(
			'pvw_wp_oauth2_instagrate_pro_is_callback_page_redirect_url',
			function () {
				return self::LITE_PAGE;
			}
		);
		$this->pro->token_manager->set_access_token( self::PROVIDER, 'pro-token' );
		$this->lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );
		$pro_handler  = Test_Admin_Handler::for_instance( $this->pro, self::PRO_PAGE );
		$lite_handler = Test_Admin_Handler::for_instance( $this->lite, self::PRO_PAGE );

		$this->visit( $this->pro->get_disconnect_url( self::PROVIDER, self::LITE_PAGE ) );
		$pro_handler->handle_disconnect();
		$lite_handler->handle_disconnect();

		$this->assertFalse( $this->pro->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertSame( 'lite-token', $this->lite->token_manager->get_access_token( self::PROVIDER ) );
	}

	public function test_refresh_sends_and_saves_that_plugins_token() {
		$this->pro->token_manager->set_access_token( self::PROVIDER, 'pro-token' );
		$this->lite->token_manager->set_access_token( self::PROVIDER, 'lite-token' );
		WP_Stubs::$remote_responses[] = json_encode( array( 'token' => 'lite-token-2', 'expires' => 1800000000 ) );

		$this->assertSame( 'lite-token-2', $this->lite->refresh_access_token( 'client', self::PROVIDER ) );

		$this->assertSame( array( 'client_id' => 'client', 'refresh_token' => 'lite-token' ), array_intersect_key( $this->query( WP_Stubs::$remote_requests[0] ), array( 'refresh_token' => 1, 'client_id' => 1 ) ) );
		$this->assertSame( 'lite-token-2', $this->lite->token_manager->get_access_token( self::PROVIDER ) );
		$this->assertSame( 1800000000, WP_Stubs::$options['lite_token']['expires'] );
		$this->assertSame( 'pro-token', $this->pro->token_manager->get_access_token( self::PROVIDER ) );
	}

	public function test_registering_admin_handlers_adds_one_set_of_hooks_each() {
		$this->pro->register_admin_handler( self::PRO_PAGE );
		$this->lite->register_admin_handler( self::LITE_PAGE );

		$this->assertCount( 6, WP_Stubs::$filters['admin_init'][10] );
	}

	/**
	 * Recreate the instances, registering in this order.
	 *
	 * @param string[] $order
	 */
	private function setUp_in_order( $order ) {
		parent::setUp();
		foreach ( $order as $plugin ) {
			if ( 'pro' === $plugin ) {
				$this->pro = WPOAuth2::instance( self::PROXY, Test_Pro_Token::class, 'instagrate_pro' );
			} else {
				$this->lite = WPOAuth2::instance( self::PROXY, Test_Lite_Token::class, 'intagrate_lite' );
			}
		}
	}

	/**
	 * Handle a callback with the handler for the page it returns to.
	 *
	 * @param string $url
	 */
	private function handle_callback( $url ) {
		$this->visit( $url );
		$page = 0 === strpos( $url, self::PRO_PAGE ) ? self::PRO_PAGE : self::LITE_PAGE;
		foreach ( array( $this->pro, $this->lite ) as $wpoauth ) {
			Test_Admin_Handler::for_instance( $wpoauth, $page )->handle_redirect();
		}
	}

	/**
	 * @param Test_Admin_Handler $handler
	 *
	 * @return string The connection notice
	 */
	private function render( $handler ) {
		ob_start();
		$handler->render_connection_notice();

		return ob_get_clean();
	}
}
