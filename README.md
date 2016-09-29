PHP Secure Configuration Checker
================================

Check current PHP configuration for potential security flaws.

Simply access this file from your webserver or run on CLI.

Author
------
This software was written by Ben Fuhrmannek, [SektionEins GmbH](https://sektioneins.de/), in an effort to automate php.ini checks and spend more time on cheerful tasks.

Idea
----

* one single file for easy distribution
* simple tests for each security related ini entry
* a few other tests - not too complicated though
* compatible with PHP >= 5.4, or if possible >= 5.0
* NO complicated/overengineered code, e.g. no classes/interfaces, test-frameworks, libraries, ... -> It is supposed to be obvious on first glance - even for novices - how this tool works and what it does!
* NO (or very few) dependencies

Usage / Installation
--------------------

* **CLI**: Simply call `php phpconfigcheck.php`. That's it. Add `-a` to see hidden results as well, `-h` for HTML output and `-j` for JSON output.

* **WEB**: Copy this script to any directory accessible by your webserver, e.g. your document root. See also 'Safeguards' below.

  The output in non-CLI mode is HTML by default. This behaviour can be changed by setting the environment variable  `PCC_OUTPUT_TYPE=text` or `PCC_OUTPUT_TYPE=json`.

  Some test cases are hidden by default, specifically skipped, ok and unknown/untested. To show all results, use `phpconfigcheck.php?showall=1`. This does not apply to JSON output, which returns all results by default.

  To control the output format in WEB mode use `phpconfigcheck.php?format=...`, where the value of `format` maybe one of `text`, `html` or `json`. For example: `phpconfigcheck.php?format=text`. The `format` parameter takes precedence over PCC_OUTPUT_TYPE.

Safeguards
----------

Most of the time it is a good idea to keep security related issues such as your PHP configuration to yourself. The following safeguards have been implemented:

* **mtime check**: This script stops working in non-CLI mode after two days. Re-arming the check can be done by `touch phpconfigcheck.php` or by copying the script to your server again (e.g. via SCP). This check can be disabled by setting the environment variable: `PCC_DISABLE_MTIME=1`, e.g. `SetEnv PCC_DISABLE_MTIME 1` in apache's `.htaccess`.

* **source IP check**: By default only localhost (127.0.0.1 and ::1) can access this script. Other hosts may be added by setting `PCC_ALLOW_IP` to a your IP address or a wildcard pattern, e.g. `SetEnv PCC_ALLOW_IP 10.0.0.*` in `.htaccess`. You may also choose to access your webserver via SSH Port forwarding, e.g. `ssh -D` or `ssh -L`.

Troubleshooting
---------------

* **disabled functions:** This scripts needs a few functions to work properly, such as `ini_get()` and `stat()`. If one of these functions is blacklisted (or not whitelisted) then execution will fail or produce invalid output. In these cases it is possible to _temporarily_ put Suhosin in simulation mode and omit disable_functions. To be on the safe side, relaxed security configuration can be done with .htaccess in a separate directory. Also, this script may be called from command line with your webserver's configuration, e.g. `php -n -c /etc/.../php.ini phpconfigcheck.php`.

* **CLI:** Older PHP versions don't known about SAPI name 'cli' and use CGI style output even on cli. Workaround: `PCC_OUTPUT_TYPE=text /opt/php/php-5.1.6/bin/php phpconfigcheck.php`

WARNING
-------

This tool will only support you setting up a secure PHP environment.
Nothing else. Your setup, software or any related configuration may still
be vulnerable, even if this tool's output suggests otherwise.

Notes
-----

* For copyright and license information, see phpconfigcheck.php and the LICENSE file.
* Issues, comments, enhancements? Please use the Github issue tracker:
  https://github.com/sektioneins/pcc/issues
