=== Force Strong Passwords ===
Contributors: MarkBerube, boogah, gyrus, simonwheatley, sparanoid, jpry, zyphonic
Tags: passwords, security, users, profile
Requires at least: 6
Tested up to: 6.5.5
Stable tag: 2.0

Forces privileged users to set a strong password.

== Description ==
Force Strong Passwords is a WordPress plugin that forces users with admin rights or rights configured to have strong passwords. The current rules are:
- Minimum 8 characters
- At least one uppercase and lowercase letter
- At least one digit
- Password not found in common password list (taken from Nation Cyber Security Centre)

This is a complete overhaul of the plugin from the fork: https://github.com/boogah/force-strong-passwords. Shamelessly taken as it has archived and abandoned since late 2020. Changes to that plugin include:
- Unit testing
- More up-to-date rules
- Compatibility with the latest WordPress version at the time of writing (6.5.5).

== Installation ==
1. Upload the `force-strong-passwords` directory into the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.

== Changelog ==

= 2.0 =

Overhaul of the plugin. Added new rules, unit testing and compatibility with the latest WordPress version at the time of writing (6.5.5).