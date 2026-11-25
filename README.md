# WP OAuth2

This is a WordPress library for connecting to third-party services with OAuth 2, using a proxy server, from inside a distributed WordPress plugin.

## Usage

Each plugin gets its own instance, named by an instance key such as its slug:

```php
use Polevaultweb\WPOAuth2\V3\WPOAuth2;

$wpoauth = WPOAuth2::instance( 'https://proxy.example.com/', My_Plugin_Access_Token::class, 'my_plugin' );
$wpoauth->register_admin_handler( admin_url( 'options-general.php?page=my-plugin' ) );
```

The token class extends `AbstractAccessToken` and stores the plugin's tokens. Without a token class, tokens go in the `wp-oauth2-tokens` site option keyed by provider, which every instance using the default class shares, so give each plugin its own token class.

Each instance keeps its login keys in its own site transient, `wp-oauth2-key-{instance_key}`, and adds `wp-oauth2-instance={instance_key}` to its callback, notice and disconnect URLs, so only its own admin handler acts on them.

## Filters

Each filter runs twice: first as `pvw_wp_oauth2_{hook}` for every instance, then as `pvw_wp_oauth2_{instance_key}_{hook}` for one instance. Both get the instance key as their last argument. Hook the second, so your callback doesn't change another plugin's login. `$wpoauth->get_filter_name( 'redirect_url' )` returns its name.

| Hook | Filters | Other arguments |
|------|---------|-----------------|
| `redirect_url` | URL the handler redirects to after a login or disconnect | |
| `is_callback_page_redirect_url` | URL of the admin page that is the callback page | |
| `provider_display_name` | provider name shown in notices | provider |
| `error_notice_message` | error message | provider display name |
| `error_notice_class` | notice class | provider display name |
| `connection_notice_class` | notice class | |
| `disconnection_notice_class` | notice class | |

## Bundling in more than one plugin

The namespace carries the API version (`V3`). Copies released before it use `Polevaultweb\WPOAuth2`, where `WPOAuth2::instance()` returns one instance shared by every plugin, so a plugin that bundles one of those can't take over a V3 instance, whichever plugin loads first.

Every plugin on a site that bundles V3 runs whichever V3 copy loaded first. Keep changes to V3 backwards compatible. A change that breaks it needs a new namespace (`V4`), and a matching change to the `autoload` entry in `composer.json`.

## Tests

`phpunit -c tests/phpunit.xml` (PHPUnit 9), without WordPress or composer.
