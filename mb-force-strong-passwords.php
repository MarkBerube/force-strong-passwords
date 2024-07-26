<?php
/**
 * Plugin Name:  Force Strong Passwords
 * Plugin URI:   https://github.com/MarkBerube/force-strong-passwords/
 * Description:  Forces privileged users to set a strong password.
 * Version:      2.0.0
 * Author:       Mark Berube & Jason Cosper
 * Author URI:   https://mjberube.com/ & http://jasoncosper.com/
 * License:      GPLv3
 * License URI:  https://www.gnu.org/licenses/gpl-3.0.txt
 * Text Domain:  force-strong-passwords
 * Domain Path:  /languages
 *
 * @link         https://mjberube.com/
 * @package      WordPress
 * @author       Mark Berube & Jason Cosper
 * @version      2.0.0
 */

global $wp_version;


// Make sure we don't expose any info if called directly.
if ( ! function_exists( 'add_action' ) ) {
	esc_html_e( "Hi there! I'm just a plugin, not much I can do when called directly.", 'mb-force-strong-passwords' );
	exit;
}


/**
 * Initialize constants.
 */

// Our plugin.
define( 'MB_FSP_PLUGIN_BASE', __FILE__ );

// Allow changing the version number in only one place (the header above).
$plugin_data = get_file_data( FSP_PLUGIN_BASE, array( 'Version' => 'Version' ) );
define( 'MB_FSP_PLUGIN_VERSION', $plugin_data['Version'] );

define( 'MB_FSP_COMMON_PASSWORD_FILE', __DIR__ . '/mb-force-strong-password-common-list.txt');

if ( ! defined( 'MB_FSP_CAPS_CHECK' ) ) {
    define( 'MB_FSP_CAPS_CHECK', 'publish_posts,upload_files,edit_published_posts' );
}

if ( ! defined( 'MB_FSP_WEAK_ROLES' ) ) {
    define('MB_FSP_WEAK_ROLES', 'subscriber,contributor');
}

// Initialize other stuff.
add_action( 'plugins_loaded', 'mb_fsp_init' );
function mb_fsp_init() {
	// Text domain for translation.
	load_plugin_textdomain( 'mb-force-strong-passwords', false, dirname( plugin_basename ( __FILE__ ) ) . '/languages/' );

	// Initializing WPHooks.
    add_action( 'validate_password_reset', 'MB_Strong_Password_Manager::validate_strong_password', 10, 2 );
	add_action( 'user_profile_update_errors', 'mb_fsp_validate_profile_update', 0, 3 );
}


/**
 * Check user profile update and throw an error if the password isn't strong.
 */
function mb_fsp_validate_profile_update( $errors, $update, $user_data ) {
    return MB_Strong_Password_Manager::validate_strong_password($errors, $user_data);
}

class MB_Strong_Password_Manager {
    /**
     * Functionality used by both user profile and reset password validation.
     */
    public static function validate_strong_password( $errors, $user_data )
    {
        list( $password, $role, $user_id, $user_name ) = self::parse_user_data( $user_data );

        if ( ( false === $password ) ||
            ( is_wp_error( $errors ) &&
            $errors->get_error_data( 'pass' ) )
        ) {
            return $errors;
        }

        if ( self::should_enforce_strong_password( $user_id, $role ) ) {
            if (
                !self::is_strong_password( $password, $user_name ) &&
                is_wp_error( $errors )
            ) { // Is this a WP error object?
                $errors->add( 'pass', apply_filters( 'mb_fsp_error_message', __( '<strong>ERROR</strong>: Please make the password a strong one.', 'mb-force-strong-passwords' ) ) );
            }
        }

        return $errors;
    }

    /**
     * Parses user data from $user_data object or $_POST global from WP form
     * @param $user_data
     * @return array
     */
    public static function parse_user_data( $user_data ): array {
        $password    = ( isset( $_POST['pass1'] ) && trim( $_POST['pass1'] ) ) ? sanitize_text_field( $_POST['pass1'] ) : false;
        $role        = isset( $_POST['role'] ) ? sanitize_text_field( $_POST['role'] ) : false;
        $user_id     = isset( $user_data->ID ) ? sanitize_text_field( $user_data->ID ) : false;
        $user_name    = isset( $_POST['user_login'] ) ? sanitize_text_field( $_POST['user_login'] ) : $user_data->user_login;

        return [ $password, $role, $user_id, $user_name ];
    }

    /**
     * Checks whether the given WP user should be forced to have a strong password.
     * @param $user_id
     * @param $role
     * @return bool
     */
    public static function should_enforce_strong_password( $user_id, $role = false ): bool
    {
        // Force strong passwords from network admin screens.
        if ( is_network_admin() ) {
            return true;
        }

        // couldn't find a user ID, use role instead
        if ( $user_id === false && $role !== false ) {
            $weak_roles = explode( ',', MB_FSP_WEAK_ROLES );
            if ( ! empty( $weak_roles ) && in_array( $role, $weak_roles ) ) {
                return false;
            }
        }

        $check_caps = explode( ',', MB_FSP_CAPS_CHECK );

        if ( ! empty( $check_caps ) ) {
            foreach ( $check_caps as $cap ) {
                if ( user_can( $user_id, $cap ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Determines if a password is strong enough
     * @param $password
     * @param $username
     * @return bool
     */
    public static function is_strong_password( $password, $username ): bool
    {
        // is at least 8 characters in length & does not match the username
        if ( strlen($password) > 8 ||  $username === $password ) {
            return false;
        }

        // more rigorous checks for a strong password
        list( $lower, $upper, $digit, $repeat, $compromised ) = array_fill( 0, 5, false );

        /**
         * iterate over each character in the password for the following rules:
         * - contains  at least one lowercase letter and at least one uppercase letter
         * - contains at least one digit
         */
        $char_count = 0;
        for ( $i = 0; $i < strlen( $password ); $i++ ) {
            if ( $i > 0 && $password[ $i ] == $password[ $i - 1 ] ) {
                $char_count++;
            } else {
                $char_count = 1;
            }

            if ( ctype_lower( $password[ $i ] ) ) {
                $lower = true;
            } elseif ( ctype_upper( $password[ $i ] ) ) {
                $upper = true;
            } elseif ( ctype_digit( $password[ $i ] ) ) {
                $digit = true;
            } elseif ( $char_count > 3 ) {
                $repeat = true;
            }
        }

        // check if the password is in the common password list
        if ( $fp = @fopen( MB_FSP_COMMON_PASSWORD_FILE, 'r' ) ) {
            $array = explode( PHP_EOL, fread($fp, filesize( MB_FSP_COMMON_PASSWORD_FILE ) ) );

            if ( array_search( $password, $array ) !== false ) {
                $compromised = true;
            }

            fclose( $fp );
        }

        // if any checks on the password are true, that means the password isn't strong enough
        return ! in_array( true, [ $lower, $upper, $digit, $repeat, $compromised ] );
    }
}