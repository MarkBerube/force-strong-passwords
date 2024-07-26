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

define( 'MB_FSP_COMMON_PASSWORD_FILE', plugin_dir_path( __DIR__ ) . '/mb-force-strong-password-common-list.txt');

if ( ! defined( 'MB_FSP_CAPS_CHECK' ) ) {
    define( 'MB_FSP_CAPS_CHECK', 'publish_posts,upload_files,edit_published_posts' );
}

if ( ! defined( 'MB_FSP_WEAK_ROLES' ) ) {
    define('MB_FSP_WEAK_ROLES', 'subscriber,contributor');
}

require plugin_dir_path( __FILE__ ) . 'includes/class-mb-strong-password-manager.php';

function mb_fsp_init() {
	// Text domain for translation.
	load_plugin_textdomain( 'mb-force-strong-passwords', false, dirname( plugin_basename ( __FILE__ ) ) . '/languages/' );

	// Initializing WPHooks.
    add_action( 'validate_password_reset', 'MB_Strong_Password_Manager::validate_strong_password', 10, 2 );
	add_action( 'user_profile_update_errors', 'mb_fsp_validate_profile_update', 0, 3 );
}

// Initialize other stuff.
add_action( 'plugins_loaded', 'mb_fsp_init' );

/**
 * Check user profile update and throw an error if the password isn't strong.
 */
function mb_fsp_validate_profile_update( $errors, $update, $user_data ) {
    return MB_Strong_Password_Manager::validate_strong_password($errors, $user_data);
}

