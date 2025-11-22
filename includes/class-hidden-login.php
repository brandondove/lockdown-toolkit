<?php
/**
 * Lockdown Tools Hidden Login Class
 *
 * Allows admins to hide the WordPress login page and redirect
 * wp-login.php requests to a custom location
 *
 * @package LockdownTools
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Lockdown_Toolkit_Hidden_Login
 */
class Lockdown_Toolkit_Hidden_Login {

	/**
	 * Option key for login page URL
	 */
	const LOGIN_PAGE_URL_OPTION = 'lockdown_tools_login_page_url';

	/**
	 * Option key for redirect URL
	 */
	const REDIRECT_URL_OPTION = 'lockdown_tools_redirect_url';

	/**
	 * Initialize the hidden login functionality
	 *
	 * @return void
	 */
	public static function init() {
		// Register settings page fields
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'admin_init', array( __CLASS__, 'add_settings_fields' ) );

		// Handle wp-login.php redirects
		add_action( 'init', array( __CLASS__, 'handle_login_redirect' ), 1 );

		// Handle custom login page
		add_action( 'init', array( __CLASS__, 'handle_custom_login_page' ), 1 );
	}

	/**
	 * Register settings for the General settings page
	 *
	 * @return void
	 */
	public static function register_settings() {
		register_setting( 'general', self::LOGIN_PAGE_URL_OPTION, array(
			'type'              => 'string',
			'sanitize_callback' => array( __CLASS__, 'sanitize_login_page_url' ),
			'show_in_rest'      => false,
		) );

		register_setting( 'general', self::REDIRECT_URL_OPTION, array(
			'type'              => 'string',
			'sanitize_callback' => array( __CLASS__, 'sanitize_redirect_url' ),
			'show_in_rest'      => false,
		) );
	}

	/**
	 * Add settings fields to the General settings page
	 *
	 * @return void
	 */
	public static function add_settings_fields() {
		add_settings_section(
			'lockdown_toolkit_hide_login',
			__( 'Hide Login Page', 'lockdown-toolkit' ),
			array( __CLASS__, 'section_callback' ),
			'general'
		);

		add_settings_field(
			self::LOGIN_PAGE_URL_OPTION,
			__( 'Login Page URL', 'lockdown-toolkit' ),
			array( __CLASS__, 'login_page_url_field' ),
			'general',
			'lockdown_toolkit_hide_login'
		);

		add_settings_field(
			self::REDIRECT_URL_OPTION,
			__( 'Redirect URL', 'lockdown-toolkit' ),
			array( __CLASS__, 'redirect_url_field' ),
			'general',
			'lockdown_toolkit_hide_login'
		);
	}

	/**
	 * Settings section callback
	 *
	 * @return void
	 */
	public static function section_callback() {
		echo wp_kses_post( __( 'Configure a custom login page location and redirect unauthorized login attempts.', 'lockdown-toolkit' ) );
	}

	/**
	 * Login page URL field callback
	 *
	 * @return void
	 */
	public static function login_page_url_field() {
		$value = get_option( self::LOGIN_PAGE_URL_OPTION );
		$site_url = home_url();
		?>
		<div style="display: flex; gap: 10px; align-items: center;">
			<span style="color: #666; font-size: 14px;"><?php echo esc_html( $site_url ); ?><strong>/</strong></span>
			<input type="text" name="<?php echo esc_attr( self::LOGIN_PAGE_URL_OPTION ); ?>" value="<?php echo esc_attr( $value ); ?>" placeholder="my-login" style="width: 300px;" />
		</div>
		<p class="description"><?php esc_html_e( 'Enter the path where your login page will be accessible (e.g., my-login). Leave empty to disable.', 'lockdown-toolkit' ); ?></p>
		<?php
	}

	/**
	 * Redirect URL field callback
	 *
	 * @return void
	 */
	public static function redirect_url_field() {
		$value = get_option( self::REDIRECT_URL_OPTION );
		$site_url = home_url();
		?>
		<div style="display: flex; gap: 10px; align-items: center;">
			<span style="color: #666; font-size: 14px;"><?php echo esc_html( $site_url ); ?><strong>/</strong></span>
			<input type="text" name="<?php echo esc_attr( self::REDIRECT_URL_OPTION ); ?>" value="<?php echo esc_attr( $value ); ?>" placeholder="404" style="width: 300px;" />
		</div>
		<p class="description"><?php esc_html_e( 'Enter the path where users should be redirected if they try to access wp-login.php directly (e.g., 404). Leave empty to redirect to the home page.', 'lockdown-toolkit' ); ?></p>
		<?php
	}

	/**
	 * Sanitize login page URL
	 *
	 * @param mixed $value The value to sanitize.
	 * @return string
	 */
	public static function sanitize_login_page_url( $value ) {
		if ( empty( $value ) ) {
			return '';
		}

		// Remove leading and trailing slashes
		$value = trim( $value, '/' );

		// Remove any query strings or fragments
		$value = strtok( $value, '?' );
		$value = strtok( $value, '#' );

		return sanitize_text_field( $value );
	}

	/**
	 * Sanitize redirect URL
	 *
	 * @param mixed $value The value to sanitize.
	 * @return string
	 */
	public static function sanitize_redirect_url( $value ) {
		if ( empty( $value ) ) {
			return '';
		}

		// Remove leading and trailing slashes
		$value = trim( $value, '/' );

		// Remove any query strings or fragments
		$value = strtok( $value, '?' );
		$value = strtok( $value, '#' );

		return sanitize_text_field( $value );
	}

	/**
	 * Handle redirects from wp-login.php
	 *
	 * @return void
	 */
	public static function handle_login_redirect() {
		// Only run this on the frontend
		if ( is_admin() ) {
			return;
		}

		// Skip POST requests (form submissions like login)
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		$login_page_url = get_option( self::LOGIN_PAGE_URL_OPTION );

		// Only proceed if login page URL is set
		if ( empty( $login_page_url ) ) {
			return;
		}

		// Check if the current request is for wp-login.php
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// Match wp-login.php requests (with or without trailing slash, with or without query string)
		if ( preg_match( '#/wp-login\.php#i', $request_uri ) ) {
			// Get redirect path, default to home page if empty
			$redirect_path = get_option( self::REDIRECT_URL_OPTION );
			if ( empty( $redirect_path ) ) {
				$redirect_url = home_url();
			} else {
				$redirect_url = home_url( '/' . $redirect_path );
			}

			wp_redirect( $redirect_url );
			exit;
		}
	}

	/**
	 * Handle custom login page requests
	 *
	 * @return void
	 */
	public static function handle_custom_login_page() {
		// Only run this on the frontend
		if ( is_admin() ) {
			return;
		}

		$login_page_url = get_option( self::LOGIN_PAGE_URL_OPTION );

		// Only proceed if option is set
		if ( empty( $login_page_url ) ) {
			return;
		}

		// Get the current request path
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// Parse the URL to get just the path
		$parsed_url = wp_parse_url( $request_uri );
		$request_path = isset( $parsed_url['path'] ) ? $parsed_url['path'] : '';

		// Construct the login page URL with leading slash
		$login_url = '/' . $login_page_url;

		// Check if the current request matches the custom login page URL
		if ( $request_path === $login_url || $request_path === $login_url . '/' ) {
			// Load the WordPress login page using the standard login template
			require_once ABSPATH . 'wp-login.php';
			exit;
		}
	}
}
