<?php
/*
[+] PHP Secure Configuration Checker - (c) 2014 - SektionEins GmbH
    -- Ben Fuhrmannek <ben.fuhrmannek@sektioneins.de>

[+] Description:
    Check current PHP configuration for potential security flaws.
    Simply access this file from your webserver or run on CLI.

[+] Idea:
    * one single file for easy distribution
    * simple tests for each security related ini entry
    * a few other tests - not too complicated though
    * compatible with PHP >= 5.4, or if possible >= 5.0
    * NO complicated/overengineered code, e.g. no classes/interfaces,
      test-frameworks, libraries, ...
        -> It is supposed to be obvious on first glance - even for novices -
           how this tool works and what it does!
    * NO (or very few) dependencies

[+] WARNING:
    This tool will only support you setting up a secure PHP environment.
    Nothing else. Your setup, software or any related configuration may still
    be vulnerable, even if this tool's output suggests otherwise.

[+] Update:
    Please check https://github.com/sektioneins/pcc

[+] License:
    This tool is licensed under the New BSD License.
    See LICENSE file for fulltext version of the license.

[+] Copyright Notes:
    Some text fragments have been copied from the printed PHP Web Security
    Poster with permission. - (C) 2009 SektionEins GmbH
    - Concept: Stefan Esser, fukami, Ben Fuhrmannek
    
*/

/*****************************************************************************/
/* *** *** *** DANGER ZONE!! *** *** *** */

// uncomment to disable IP restrictions by default
// WARNING: better keep access restricted, e.g. set PCC_ALLOW_IP=10.0.0.*
//putenv("PCC_ALLOW_IP=*");

// This script will deactivate after 48 hours automatically.
// To disable this feature, uncomment the line below.
// WARNING: better keep this commented out unless further restrictions apply, e.g. IP check
//putenv("PCC_DISABLE_MTIME=1");

/*****************************************************************************/

$pcc_name = "PHP Secure Configuration Checker";
$pcc_version = "0.1-dev";
$pcc_copy = "(c) 2014 SektionEins GmbH / Ben Fuhrmannek";
$pcc_date = "2014-08-15"; // release date for update check
$pcc_url = "https://github.com/sektioneins/pcc"; // download URL

/*****************************************************************************/

// test result codes
define("TEST_CRITICAL", "critical"); // critical problem found.
define("TEST_HIGH", "high"); // high problem found.
define("TEST_MEDIUM", "medium"); // medium. this may be a problem.
define("TEST_LOW", "low"); // low. boring problem found.
define("TEST_MAYBE", "maybe"); // potential security risk. please check manually.
define("TEST_COMMENT", "comment"); // odd, but still worth mentioning.
define("TEST_OK", "ok"); // everything is fine. move along.
define("TEST_SKIPPED", "skipped"); // probably not applicable here.
define("TEST_UNKNOWN", "unknown"); // something is unknown.

// globals
$cfg = array(	'output_type' => 'text',
				'showall' => 0,
				'result_codes_default' => array(TEST_CRITICAL, TEST_HIGH, TEST_MEDIUM, TEST_LOW, TEST_MAYBE, TEST_COMMENT),
				'need_update' => 0);
$all_result_codes = array(TEST_CRITICAL, TEST_HIGH, TEST_MEDIUM, TEST_LOW, TEST_MAYBE, TEST_COMMENT, TEST_OK, TEST_SKIPPED, TEST_UNKNOWN);
$trbs = array(); // test result by severity, e.g. $trbs[TEST_OK][...]
foreach ($all_result_codes as $v) { $trbs[$v] = array(); }
$cfg['s1_logo'] = "data:image/gif;base64,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";
$cfg['s1_logo_aa'] = "
            `.-:///:-.` /+-`        
        `/shmmmmmmmmmm:.dmmds:      
     `/ymmmdyo/::-:://  `:sdmmh:    
    /hmmdo-                `+dmmy.  
  `smmd/`                    .ymmh` 
 `hmmy.                        /-`  
 ymmy`                        -oyy  
-mmm-                         .dmm:    ---   $pcc_name 
+mmh                           ymmo    ---   Version $pcc_version
ommh                           ymms    ---   $pcc_copy
:mmd.                         `dmm/    ---- https://sektioneins.de/
`hmms                         +mmd` 
 -dmmo                       +mmd:  
  -dmmy.                   .smmd:   
   `smmms-               -sdmmy.    
     -sdmmds+:.``  `.-/sdmmms-      
       `/sdmmmmmdddmmmmmds/`        
           .:/ossssso+:.            ";

/*****************************************************************************/


// are we running as cli?
if (php_sapi_name() == "cli") {
	$cfg['output_type'] = "text";
	$cfg['is_cli'] = true;
	
} else {
	$cfg['output_type'] = "html";
	$cfg['is_cli'] = false;
	
	// mtime check
	$cfg['PCC_DISABLE_MTIME'] = getenv("PCC_DISABLE_MTIME");
	$cfg['SCRIPT_FILENAME'] = getenv("SCRIPT_FILENAME");
	if (!$cfg['PCC_DISABLE_MTIME'] && $cfg['SCRIPT_FILENAME'] !== FALSE) {
		if (filemtime($cfg['SCRIPT_FILENAME']) + 2*24*3600 < time()) {
			die("mtime check failed. - For security reasons this script was disabled automatically after a while.\n Please 'touch' me, or set the environment variable 'PCC_DISABLE_MTIME=1' (e.g. 'SetEnv PCC_DISABLE_MTIME 1' for apache/.htaccess)");
		}
	}
	
	// IP check
	$cfg['REMOTE_ADDR'] = getenv("REMOTE_ADDR");
	$cfg['PCC_ALLOW_IP'] = getenv("PCC_ALLOW_IP");
	if ($cfg['REMOTE_ADDR'] !== FALSE) {
		if (!in_array($cfg['REMOTE_ADDR'], array("127.0.0.1", "::1"), TRUE)
			&& !($cfg['PCC_ALLOW_IP'] !== FALSE && fnmatch($cfg['PCC_ALLOW_IP'], $cfg['REMOTE_ADDR']))) {
			die("Access denied. - Your IP is not cleared. Please set PCC_ALLOW_IP to a your IP address or a wildcard pattern, e.g. 'SetEnv PCC_ALLOW_IP 10.0.0.*'");
		}
	}

	// output type
	if (getenv('PCC_OUTPUT_TYPE') === 'text') {
		$cfg['output_type'] = 'text';
		header("Content-Type: text/plain; charset=utf-8");
	}

	// do not hide unknown/skipped/ok tests
	if (isset($_GET['showall']) && $_GET['showall'] === "1") {
		$cfg['showall'] = 1;
	}
}

// detect OS
$cfg['is_win'] = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

// detect CGI
$cfg['is_cgi'] = (substr(php_sapi_name(), 0, 3) === 'cgi');

/*****************************************************************************/

	
// functions
function tdesc($name, $desc=NULL) {
	return array(
		"name" => $name,
		"desc" => $desc,
		"result" => NULL,
		"reason" => NULL,
		"recommendation" => NULL
	);
}

function tres($meta, $result, $reason=NULL, $recommendation=NULL) {
	global $trbs;
	$res = array_merge($meta, array("result" => $result, "reason" => $reason, "recommendation" => $recommendation));
	$trbs[$result][] = $res;
}

function ini_atol($val)
{
	$ret = intval($val);
	$val = strtolower($val);
	switch (substr($val, -1)) {
		case 'g': $ret *= 1024;
		case 'm': $ret *= 1024;
		case 'k': $ret *= 1024;
	}
	return $ret;
}

function ini_list($val)
{
	if ($val == "") {
		return NULL;
	}
	$ret = split('[, ]+', $val);
	if (count($ret) == 1 && $ret[0] == "") {
		return NULL;
	}
	return $ret;
}

function is_writable_or_chmodable($fn)
{
	if (!extension_loaded("posix")) { return is_writable($fn); }
	$stat = stat($fn);
	if (!$stat) { return false; }
	$myuid = posix_getuid();
	$mygids = posix_getgroups();
	if ($myuid == 0 ||
			$myuid == $stat['uid'] ||
			in_array($stat['gid'], $mygids) && $stat['mode'] & 0020 ||
			$stat['mode'] & 0002) {
		return true;
	}
	return false;
}


/*****************************************************************************/

$helptext = array(
	"display_errors" => "Error messages can divulge information about the inner workings of an application and may include private information such as Session-ID, personal data, database structures, source code exerpts. It is recommended to log errors, but not to display them on live systems.",
	'log_errors' => "While it may be a good idea to avoid logging altogether from a privacy point of view, monitoring the error log of an application can lead to detecting attacks, programming and configuration errors.",
	'expose_php' => "Knowing the exact PHP version - sometimes including patchlevel and operating system - is a good start for automated attack tools. Best not to share this information.",
	'max_execution_time' => "In order to prevent denial-of-service attacks where an attacker tries to keep your server's CPU busy, this value should be set to the lowest possible value, e.g. 30 (seconds).",
	'max_input_time' => "It may be useful to limit the time a script is allowed to parse input. This should be decided on a per application basis.",
	'max_input_nesting_level' => "Deep input nesting is only required in rare cases and may trigger unexpected ressource limits.",
	'memory_limit' => "A high memory limit may easy lead lead to ressource exhaustion and thus make your application vulnerable to denial-of-service attacks. This value should be set approximately 20% above empirically gathered maximum memory requirement.",
	'post_max_size' => "Setting the maximum allowed POST size to a high value may lead to denial-of-service from memory exhaustion. If your application does not need huge file uploads, consider setting this option to a lower value. Note: File uploads have to be covered by this setting as well.",
	'post_max_size>memory_limit' => "post_max_size must be lower than memory_limit. Otherwise, a simple POST request will let PHP reach the configured memory limit and stop execution. Apart from denial-of-service an attacker may try to split a transaction, e.g. let PHP execute only a part of a program.",
	'upload_max_filesize' => "This value should match the file size actually required.",
	'allow_url_fopen' => "Deactivate, if possible. Allowing URLs in fopen() can be a suprising side-effect for unexperienced developers. Even if deactivated, it is still possible to receive content from URLs, e.g. with curl.",
	'allow_url_include' => "This flag should remain deactivated for security reasons.",
	'magic_quotes' => "This option should be deactivated. Instead, user input should be escaped properly and handled in a secure way when building database queries. The use of magic quotes or similar behaviour is highly discouraged. Current PHP versions do not support this feature anymore.",
	'enable_dl' => "Deactivate this option to prevent arbitrary code to be loaded during runtime (see dl()).",
	'disable_functions' => "Potentially dangerous and unused functions should be deactivated, e.g. system().",
	'disable_classes' => "Potentially dangerous and unused classes should be deactivated.",
	'request_order' => "It is recommended to use GP to register GET and POST with REQUEST.",
	'variables_order' => "Changing this setting is usually not necessary; however, the ENV variables are rarely used.",
	'auto_globals_jit' => "Unless access to these variables is done through variable variables this option can remain activated.",
	'register_globals' => "This relic from the past is not available in current PHP versions. If it is there anyway, keep it deactivated! Please.",
	'file_uploads' => "If an application does not require HTTP file uploads, this setting should be deactivated.",
	'filter.default' => "This should only be set if the application is specifically designed to handle filtered values. Usually it is considered bad practice to filter all user input in one place. Instead, each user input should be validated and then escaped/encoded according to its context.",
	'open_basedir' => "Usually it is a good idea to restrict file system access to directories related to the application, e.g. the document root.",
	'session.save_path' => "This path should be set to a directory unique to your application, but outside the document root, e.g. /opt/php_sessions/application_1. If this application is the only application on your server, or a custom storage mechanism for sessions has been implemented, or you don't need sessions at all, then the default should be fine.",
	'session.cookie_httponly' => "This option controls if cookies are tagged with httpOnly which makes them accessible by HTTP only and not by the JavaScript. httpOnly cookies are supported by all major browser vendors and therefore can be instrumental in minimising the danger of session hijacking. It should either be activated here or in your application with session_set_cookie_params().",
	'session.cookie_secure' => "This options controls if cookies are tagged as secure and should therefore be sent over SSL encrypted connections only. It should either be activated here or in your application with session_set_cookie_params().",
	'session.cookie_lifetime' => "Not limiting the cookie lifetime increases the chance for an attacker to be able to steal the session cookie. Depending on your application, this should be set to a reasonable value here or with session_set_cookie_params().",
	'session.referer_check' => "PHP can invalidate a session ID if the submitted HTTP Referer does not contain a configured substring. The Referer can be set by a custom client/browser or plugins (e.g. Flash, Java). However it may prevent some cases of CSRF attacks, where the attacker can not control the client's Referer.",
	'session.use_strict_mode' => "If activated, PHP will regenerate unknown session IDs. This effectively counteracts session fixation attacks.",
	'session.use_cookies' => "If activated, PHP will store the session ID in a cookie on the client side. This is recommended.",
	'session.use_only_cookies' => "PHP will send the session ID only via cookie to the client, not e.g. in the URL. Please activate.",
	'always_populate_raw_post_data' => "In a shared hosting environment it should not be the default to let the unexperienced user parse raw POST data themselves. Otherwise, this options should only be used, if accessing the raw POST data is actually required.",
	'arg_separator' => "The usual argument separator for parsing a query string is '&'. Standard libraries handling URLs will possibly not be compatible with custom separators, which may lead to unexpected behaviour. Also, additional parsers - such as a WAF or logfile analyzers - have to be configured accordingly.",
	'assert.active' => "assert() evaluates code just like eval(). Unless it is actually required in a live environment, which is almost certainly not the case, this feature should be deactivated.",
	'auto_append_file' => "PHP is automatically executing an extra script for each request. An attacker may have planted it there. If this is unexpected, deactivate.",
	'cli.pager' => "PHP executes an extra script to process CLI output. An attacker may have planted it there. If this is unexpected, deactivate.",
	'cli.prompt' => "An overlong CLI prompt may indicate incorrect configuration. Please check manually.",
	'curl.cainfo' => "Incorrect configuration of this option may prevent cURL from validating a certificate.",
	'docref_*' => "This setting may reveal internal ressources, e.g. internal server names. Setting docref_root or docref_ext implies HTML output of error messages, which is bad practice for live environments and may reveal useful information to an attacker as well.",
	'default_charset=empty' => "Not setting the default charset can make your application vulnerable to injection attacks based on incorrect interpretation of your data's character encoding. If unsure, set this to 'UTF-8'. HTML output should should contain the same value, e.g. <meta charset=\"utf-8\"/>. Also, your webserver can be configured accordingly, e.g. 'AddDefaultCharset UTF-8' for Apache2.",
	'default_charset=typo' => "Change this to 'UTF-8' immediately.",
	'default_charset=iso-8859' => "There is nothing wrong with ISO8859 charsets. However, the hipster way to deliver content tries not to discriminate and allows multibyte characters, e.g. Klingon unicode characters, too. Some browsers may even be so bold as to use a multibyte encoding anyway, regardless of this setting.",
	'default_charset=custom' => "A custom charset is perfectly fine as long as your entire chain of character encoding knows about this. E.g. the application, database connections, PHP, the webserver, ... all have the same encoding or know how to convert appropriately. In particular calls to escaping functions such as htmlentities() and htmlspecialchars() must be called with the correct encoding.",
	'default_mimetype' => "Please set a default mime type, e.g. 'text/html' or 'text/plain'. The mime type should always reflect the actual content. But it is a good idea to define a fallback here anyway. An incorrectly stated mime type can lead to injection attacks, e.g. using 'text/html' with JSON data may lead to XSS.",
	'default_socket_timeout' => "By delaying the process to establish a socket connection, an attacker may be able to do a denial-of-service (DoS) attack. Please set this value to a reasonably small value for your environment, e.g. 10.",
	'doc_root=empty' => "The PHP documentation strongly recommends to set this value when using CGI and cgi.force_redirect is off.",
	'error_append_string' => "PHP adds additional output to error messages. If planted by an attacker, this string may contain script content and lead to XSS. Please check.",
	'error_reporting' => "PHP error reporting can provide useful information about misconfiguration and programming errors, as well as possible attacks. Please consider setting this value.",
	'extension_dir' => "An attacker may try to leave a PHP extension in the extensions directory. This directory should not be writable and the web user must not be able to change file permissions",
	'exit_on_timeout' => "In Apache 1 mod_php may run into an 'inconsistent state', which is always bad. If possible, turn this feature on.",
	'filter.default' => "Using a default filter or sanitizer for all PHP input is generally not considered good practice. Instead, each input should be handled by the application individually, e.g. validated, sanitized, filtered, then escaped or encoded. The default value is 'unsafe_raw'.",
	'highlight.*' => "Your color value is suspicious. An attacker may have managed to inject something here. Please check manually.",
	'iconv.internal_encoding!=empty' => "Starting with PHP 5.6 this value is derived from 'default_charset' and can safely be left empty.",
	
	/* Suhosin */
	'suhosin.simulation' => "During initial deployment of Suhosin, this flag should be switched on to ensure that the application continues to work under the new configuration. After carefully evaluating Suhosin's log messages, you may consider switching the simulation mode off.",
	'suhosin.log.syslog' => "Logging to syslog should be used here.",
	'suhosin.log.phpscript' => "This should only be used in exceptional cases for classes of errors that could occur during script execution.",
	'suhosin.executor.max_depth' => "Defines the maximum stack depth that is per- mitted during the execution of PHP scripts. If the stack depth is exceeded, the script will be terminated. This setting should be set to a value that does not interfere with the application, but at the same time does not allow to crash the PHP interpreter, e.g. 500.",
	'suhosin.executor.include.max_traversal' => "Defines how often '../' may occur in filenames for include-statements before it is considered to be an attack. A value of zero deactivates the feature. Most PHP-applications do not require a value greater than 5.",
	'suhosin.*.cryptkey' => "This protection is less effective with a weak key. Please generate a stronger passphrase, e.g. with 'apg -m 32'.",
	'suhosin.cookie.encrypt=on' => "Be aware, that even encrypted cookie values are still user input and cannot be trusted without proper input handling.",
	'suhosin.cookie.encrypt=off' => "Suhosin can transparently encrypt cookies. This feature makes attacks based on tampering with a cookie value much harder. If at all possible, this feature should always be activated.",
	'suhosin.*.disallow_nul' => "Unless binary data is handled unencoded - which would be very obscure - this feature wants to remain enabled.",
	'suhosin.*.max_value_length=off' => "By disabling this protection PHP will be exposed to input variables of arbitrary length. It is highly recommended to set this value to the maximum length one variable is supposed to have. With file uploads in mind, request and post limits can be set to a high value.",
	'suhosin.*.max_value_length=default' => "The default value set as maximum length for each variable may be too small for some applications.",
	'suhosin.*.disallow_ws' => "Unless your application needs variable names to start with whitespace, please consider turning this option on.",
	'suhosin.*.max_name_length=off' => "The variable name length should be limited. Please set an appropriate value, e.g. 64.",
	'suhosin.log.script.name' => "An attacker may try to inject code into the logging script. Better change file permissions to read-only access.",
	'suhosin.log.script.name/chmod' => "The logging script is not set writable, but the current user has the right to change the access permission. Please change the file's owner."
);

// php.ini checks
foreach (ini_get_all() as $k => $v) {
	$v = $v["local_value"]; // for compatibility with PHP <5.3.0 ini_get_all() is not called with the second 'detail' parameter.

	$meta = tdesc("php.ini / $k");
	$result = NULL;
	$reason = NULL;
	$recommendation = NULL;
	if (isset($helptext[$k])) { $recommendation = $helptext[$k]; }

	switch ($k) {
	case 'display_errors':
		if ($v == "1") {
			list($result, $reason) = array(TEST_MEDIUM, "display_errors is on.");
		}
		break;
	case 'display_startup_errors':
		if ($v == "1") {
			list($result, $reason) = array(TEST_MEDIUM, "display_startup_errors is on.");
			$recommendation = $helptext['display_errors'];
		}
		break;
	case 'log_errors':
		if ($v != "1") {
			list($result, $reason) = array(TEST_LOW, "You are not logging errors.");
		}
		break;
	case 'expose_php':
		if ($v == "1") {
			list($result, $reason) = array(TEST_LOW, "PHP is exposed by HTTP headers.");
		}
		break;
	case 'max_execution_time':
		if (intval($v) == 0) {
			list($result, $reason) = array(TEST_MEDIUM, "Execution time is not limited.");
		} elseif (intval($v) >= 300) {
			list($result, $reason) = array(TEST_LOW, "Execution time limit is rather high.");
		}
		break;
	case 'max_input_time':
		if ($v == "-1") {
			list($result, $reason) = array(TEST_MAYBE, "Input parsing time not limited.");
		}
		break;
	case 'max_input_nesting_level':
		if (intval($v) > 128) {
			list($result, $reason) = array(TEST_MEDIUM, "Input nesting level extremely high.");
		} elseif (intval($v) > 64) {
			list($result, $reason) = array(TEST_MAYBE, "Input nesting level higher than usual.");
		}
		break;
	case 'memory_limit':
		$v = ini_atol($v);
		if ($v < 0) {
			list($result, $reason) = array(TEST_HIGH, "Memory limit deactivated.");
		} elseif (ini_atol($v) >= 128*1024*1024) { // default value
			list($result, $reason) = array(TEST_MAYBE, "Memory limit is 128M or more.");
		}
		break;
	case 'post_max_size':
		$tmp = ini_atol(ini_get('memory_limit'));
		$v = ini_atol($v);
		if ($tmp < 0) {
			if ($v >= ini_atol('2G')) {
				list($result, $reason) = array(TEST_MAYBE, "post_max_size is >= 2G.");
			}
			break;
		}
		if ($v > $tmp) {
			list($result, $reason) = array(TEST_HIGH, "post_max_size is greater than memory_limit.");
			$recommendation = $helptext['post_max_size>memory_limit'];
		}
		break;
	case 'upload_max_filesize':
		if ($v === "2M") {
			list($result, $reason) = array(TEST_COMMENT, "default value.");
		} elseif (ini_atol($v) >= ini_atol("2G")) {
			list($result, $reason) = array(TEST_MAYBE, "value is rather high.");
		}
		break;
	case 'allow_url_fopen':
		if ($v == "1") {
			list($result, $reason) = array(TEST_HIGH, "fopen() is allowed to open URLs.");
		}
		break;
	case 'allow_url_include':
		if ($v == "1") {
			list($result, $reason) = array(TEST_HIGH, "include/require() can include URLs.");
		}
		break;
	case 'magic_quotes_gpc':
		if (get_magic_quotes_gpc()) {
			list($result, $reason) = array(TEST_HIGH, "magic quotes activated.");
			$recommendation = $helptext['magic_quotes'];
		}
		break;
	case 'magic_quotes_runtime':
		if (get_magic_quotes_runtime()) {
			list($result, $reason) = array(TEST_HIGH, "magic quotes activated.");
			$recommendation = $helptext['magic_quotes'];
		}
		break;
	case 'magic_quotes_sybase':
		if ($v != "0") {
			list($result, $reason) = array(TEST_HIGH, "magic quotes activated.");
			$recommendation = $helptext['magic_quotes'];
		}
		break;
	case 'enable_dl':
		if ($v == "1") {
			list($result, $reason) = array(TEST_HIGH, "PHP can load extensions during runtime.");
		}
		break;
	case 'disable_functions':
		$v = ini_list($v);
		if (!$v) {
			list($result, $reason) = array(TEST_MEDIUM, "no functions disabled.");
		}
		break;
	case 'disable_classes':
		$v = ini_list($v);
		if (!$v) {
			list($result, $reason) = array(TEST_MEDIUM, "no classes disabled.");
		}
		break;
	case 'request_order':
		$v = strtoupper($v);
		if ($v === "GP") {break;} // ok
		if (strstr($v, 'C') !== FALSE) {
			list($result, $reason) = array(TEST_MAYBE, "cookie values in $_REQUEST.");
		}
		if (strstr(str_replace('C', $v, ''), 'PG') !== FALSE) {
			list($result, $reason) = array(TEST_LOW, "GET overrides POST in $_REQUEST.");
		}
		break;
	case 'variables_order':
		if ($v === "GPCS") { break; }
		if ($v !== "EGPCS") {
			list($result, $reason) = array(TEST_COMMENT, "custom variables_order.");
		} else {
			$result = TEST_OK; // result set includes default helptext
		}
		break;
	case 'auto_globals_jit':
		$result = TEST_OK;
		break;
	case 'register_globals':
		if ($v !== "" && $v !== "0") {
			list($result, $reason) = array(TEST_CRITICAL, "register_globals is on.");
		}
		break;
	case 'file_uploads':
		if ($v == "1") {
			list($result, $reason) = array(TEST_MAYBE, "file uploads are allowed.");
		}
		break;
	case 'filter.default':
		if ($v !== "unsafe_raw") {
			list($result, $reason) = array(TEST_MAYBE, "default input filter set.");
		}
		break;
	case 'open_basedir':
		if ($v == "") {
			list($result, $reason) = array(TEST_LOW, "open_basedir not set.");
		}
		break;
	case 'session.save_path':
		if ($v == "") {
			list($result, $reason) = array(TEST_MAYBE, "session save path not set.");
		}
		break;
	case 'session.cookie_httponly':
		if ($v != "1") {
			list($result, $reason) = array(TEST_MAYBE, "no implicit httpOnly-flag for session cookie.");
		}
		break;
	case 'session.cookie_secure':
		if ($v != "1") {
			list($result, $reason) = array(TEST_MAYBE, "no implicit secure-flag for session cookie.");
		}
		break;
	case 'session.cookie_lifetime':
		if ($v == "0") {
			list($result, $reason) = array(TEST_MAYBE, "no implicit lifetime for session cookie.");
		}
		break;
	case 'session.referer_check':
		if ($v === "") {
			list($result, $reason) = array(TEST_COMMENT, "referer check not activated.");
		}
		break;
	case 'session.use_strict_mode':
		if ($v != "1") {
			list($result, $reason) = array(TEST_MEDIUM, "strict mode not activated.");
		}
		break;
	case 'session.use_cookies':
		if ($v != "1") {
			list($result, $reason) = array(TEST_HIGH, "Session ID not stored in cookie.");
		}
		break;
	case 'session.use_only_cookies':
		if ($v != "1") {
			list($result, $reason) = array(TEST_HIGH, "Session ID not limited to cookie.");
		}
		break;
	case 'always_populate_raw_post_data':
		if ($v != "0") {
			list($result, $reason) = array(TEST_COMMENT, "HTTP_RAW_POST_DATA is available.");
		}
		break;
	case 'arg_separator.input':
	case 'arg_separator.output':
		if ($v !== "&") {
			list($result, $reason) = array(TEST_MAYBE, "unusual arg separator.");
			$recommendation = $helptext['arg_separator'];
		}
		break;
	case 'assert.active':
		if ($v == "1") {
			list($result, $reason) = array(TEST_MEDIUM, "assert is active.");
		}
		break;
	case 'auto_append_file':
	case 'auto_prepend_file':
		if ($v !== NULL && $v !== "") {
			list($result, $reason) = array(TEST_MAYBE, "$k is set.");
			$recommendation = $helptext['auto_append_file'];
		}
		break;
	case 'cli.pager':
		if ($v !== NULL && $v !== "") {
			list($result, $reason) = array(TEST_MAYBE, "CLI pager set.");
		}
		break;
	case 'cli.prompt':
		if ($v !== NULL && strlen($v) > 32) {
			list($result, $reason) = array(TEST_MAYBE, "CLI prompt is rather long (>32).");
		}
		break;
	case 'curl.cainfo':
		if ($v !== "") {
			if (substr($v, 0, 1) !== DIRECTORY_SEPARATOR || $is_win && substr($v, 1, 2) !== ":" . DIRECTORY_SEPARATOR) {
				list($result, $reason) = array(TEST_LOW, "CURLOPT_CAINFO must be an absolute path.");
			} elseif (!is_readable($v)) {
				list($result, $reason) = array(TEST_LOW, "CURLOPT_CAINFO is set but not readable.");
			}
			
		}
		break;
	case 'docref_root':
	case 'docref_ext':
		if ($v !== NULL && $v !== "") {
			list($result, $reason) = array(TEST_LOW, "docref is set.");
			$recommendation = $helptext['docref_*'];
		}
		break;
	case 'default_charset':
		if ($v == "") {
			list($result, $reason) = array(TEST_HIGH, "default charset not explicitly set.");
			$recommendation = $helptext['default_charset=empty'];
		} elseif (stripos($v, "iso-8859") === 0) {
			list($result, $reason) = array(TEST_MAYBE, "charset without multibyte support.");
			$recommendation = $helptext['default_charset=iso-8859'];
		} elseif (strtolower($v) == "utf8") {
			list($result, $reason) = array(TEST_HIGH, "'UTF-8' misspelled (without dash).");
			$recommendation = $helptext['default_charset=typo'];
		} elseif (strtolower($v) == "utf-8") {
			// ok.
		} else {
			list($result, $reason) = array(TEST_COMMENT, "custom charset.");
			$recommendation = $helptext['default_charset=custom'];
		}
		break;
	case 'default_mimetype':
		if ($v == "") {
			list($result, $reason) = array(TEST_HIGH, "default mimetype not set.");
		}
		break;
	case 'default_socket_timeout':
		if (intval ($v) > 60) {
			list($result, $reason) = array(TEST_LOW, "default socket timeout rather big.");
		}
		break;
	case 'doc_root':
		if (!$cfg['is_cgi']) {
			list($result, $reason) = array(TEST_SKIPPED, "no CGI environment.");
			break;
		}
		if (ini_get('cgi.force_redirect')) {
			list($result, $reason) = array(TEST_SKIPPED, "cgi.force_redirect is on instead.");
			break;
		}
		if ($v == "") {
			list($result, $reason) = array(TEST_MEDIUM, "doc_root not set.");
			$recommendation = $helptext['doc_root=empty'];
		}
		break;
	case 'error_prepend_string':
	case 'error_append_string':
		if ($v !== NULL && $v !== "") {
			list($result, $reason) = array(TEST_MAYBE, "$k is set.");
			$recommendation = $helptext['error_append_string'];
		}
		break;
	case 'error_reporting':
		if ($v === NULL || $v == 0) {
			list($result, $reason) = array(TEST_LOW, "error reporting is off.");
		}
		break;
	case 'extension_dir':
		if ($v !== NULL && $v !== "") {
			if (realpath($v) === FALSE) {
				list($result, $reason) = array(TEST_SKIPPED, "path is invalid or not accessible.");
			} elseif (is_writable($v) || is_writable_or_chmodable($v)) {
				list($result, $reason) = array(TEST_HIGH, "path is writable or chmod-able.");
			}
		}
		break;
	case 'exit_on_timeout':
		if (!isset($_SERVER["SERVER_SOFTWARE"]) || strncmp($_SERVER["SERVER_SOFTWARE"], "Apache/1", strlen("Apache/1")) !== 0) {
			list($result, $reason) = array(TEST_SKIPPED, "only relevant for Apache 1.");
		} elseif ($v != "1") {
			list($result, $reason) = array(TEST_LOW, "not enabled.");
		}
		break;
	case 'filter.default':
		if ($v !== "unsafe_raw") {
			list($result, $reason) = array(TEST_MAYBE, "global input filter is set.");
		}
		break;
	case 'highlight.bg':
	case 'highlight.comment':
	case 'highlight.default':
	case 'highlight.html':
	case 'highlight.keyword':
	case 'highlight.string':
		if (extension_loaded('pcre') && preg_match('/[^#a-z0-9]/i', $v) || strlen($v) > 7 || strpos($v, '"') !== FALSE) {
			list($result, $reason) = array(TEST_MEDIUM, "suspicious color value.");
			$recommendation = $helptext['highlight.*'];
		}
		break;
	case 'iconv.internal_encoding':
	case 'iconv.input_encoding':
	case 'iconv.output_encoding':
		if (PHP_MAJOR_VERSION > 5 || PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 6) {
			if ($v !== "") {
				list($result, $reason) = array(TEST_COMMENT, "not empty.");
				$recommendation = $helptext['iconv.internal_encoding!=empty'];
			}
		} else {
			list($result, $reason) = array(TEST_SKIPPED, "not PHP >=5.6");
		}
		break;
	
	/* ===== Suhosin ===== */
	case 'suhosin.simulation':
		if ($v == "1") {
			list($result, $reason) = array(TEST_MAYBE, "Suhosin is in simulation mode.");
		}
		break;
	case 'suhosin.log.syslog':
		if ($v === NULL || $v == "0") {
			list($result, $reason) = array(TEST_COMMENT, "Suhosin doesn't log to syslog.");
		}
		break;
	case 'suhosin.log.phpscript':
		if ($v !== NULL && $v != "0") {
			list($result, $reason) = array(TEST_COMMENT, "PHP-script for logging.");
		}
		break;
	case 'suhosin.executor.max_depth':
		if (intval($v) == 0) {
			list($result, $reason) = array(TEST_LOW, "stack depth not limited.");
		}
		break;
	case 'suhosin.executor.include.max_traversal':
		if (intval($v) == 0) {
			list($result, $reason) = array(TEST_LOW, "path traversal (include) not limited.");
		}
		break;
	case 'suhosin.cookie.cryptkey':
	case 'suhosin.session.cryptkey':
		$tmp = explode('.', $k);
		if (ini_get('suhosin.'. $tmp[1] . '.encrypt')) {
			if ($v === "") {
				list($result, $reason) = array(TEST_HIGH, "encryption used, but key not set.");
				$recommendation = $helptext['suhosin.*.cryptkey'];
			} elseif (strlen($v) < 16) {
				list($result, $reason) = array(TEST_MEDIUM, "key is very short.");
				$recommendation = $helptext['suhosin.*.cryptkey'];
			}
		}
		break;
	case 'suhosin.cookie.encrypt':
		if ($v == "1") {
			list($result, $reason) = array(TEST_COMMENT, "cookie encryption on.");
			$recommendation = $helptext['suhosin.cookie.encrypt=on'];
		} else {
			list($result, $reason) = array(TEST_MEDIUM, "cookie encryption off.");
			$recommendation = $helptext['suhosin.cookie.encrypt=off'];
		}
		break;
	case 'suhosin.cookie.disallow_nul':
	case 'suhosin.get.disallow_nul':
	case 'suhosin.post.disallow_nul':
	case 'suhosin.request.disallow_nul':
		if ($v != "1") {
			list($result, $reason) = array(TEST_HIGH, "nul-protection off.");
			$recommendation = $helptext['suhosin.*.disallow_nul'];
		}
		break;
	case 'suhosin.get.disallow_ws':
	case 'suhosin.post.disallow_ws':
	case 'suhosin.cookie.disallow_ws':
		if ($v != "1" && ini_get('suhosin.request.disallow_ws') != "1") {
			list($result, $reason) = array(TEST_LOW, "default value.");
			$recommendation = $helptext['suhosin.*.disallow_ws'];
		}
		break;
	case 'suhosin.request.max_value_length':
		if (intval($v) == 0 &&
				(intval(ini_get('suhosin.get.max_value_length')) == 0 ||
				intval(ini_get('suhosin.post.max_value_length')) == 0 ||
				intval(ini_get('suhosin.cookie.max_value_length')) == 0)) {
			list($result, $reason) = array(TEST_MEDIUM, "value length not limited.");
			$recommendation = $helptext['suhosin.*.max_value_length=off'];
		} elseif (intval($v) == 1000000) { // default value
			list($result, $reason) = array(TEST_COMMENT, "default value.");
			$recommendation = $helptext['suhosin.*.max_value_length=default'];
		}
		break;
	case 'suhosin.get.max_value_length':
	case 'suhosin.post.max_value_length':
	case 'suhosin.cookie.max_value_length':
		if (intval($v) == 0 && intval(ini_get('suhosin.request.max_value_length')) == 0) {
			list($result, $reason) = array(TEST_MEDIUM, "value length not limited.");
			$recommendation = $helptext['suhosin.*.max_value_length=off'];
		} elseif ($k === 'suhosin.get.max_value_length' && intval($v) == 512 ||
				$k == 'suhosin.post.max_value_length' && intval($v) == 1000000 ||
				$k == 'suhosin.cookie.max_value_length' && intval($v) == 10000) { // default value
			list($result, $reason) = array(TEST_COMMENT, "default value.");
			$recommendation = $helptext['suhosin.*.max_value_length=default'];
		}
		break;
	case 'suhosin.request.max_varname_length':
		if (intval($v) == 0 &&
			(intval(ini_get('suhosin.get.max_name_length')) == 0 ||
			intval(ini_get('suhosin.post.max_name_length')) == 0 ||
			intval(ini_get('suhosin.cookie.max_name_length')) == 0)) {
				list($result, $reason) = array(TEST_MEDIUM, "varname length not limited.");
				$recommendation = $helptext['suhosin.*.max_name_length=off'];
			}
		break;	
	case 'suhosin.get.max_name_length':
	case 'suhosin.post.max_name_length':
	case 'suhosin.cookie.max_name_length':
		if (intval($v) == 0 && intval(ini_get('suhosin.request.max_varname_length')) == 0) {
			list($result, $reason) = array(TEST_MEDIUM, "varname length not limited.");
			$recommendation = $helptext['suhosin.*.max_name_length=off'];
		}
		break;
	case 'suhosin.log.script.name':
	case 'suhosin.log.phpscript.name':
		if ($v !== "") {
			if (is_writable($v)) {
				list($result, $reason) = array(TEST_HIGH, "logging script is writable.");
				$recommendation = $helptext['suhosin.log.script.name'];
			} elseif (is_writable_or_chmodable($v)) {
				list($result, $reason) = array(TEST_MEDIUM, "logging script is potentially writable.");
				$recommendation = $helptext['suhosin.log.script.name/chmod'];
			}
		}
		break;
	
	/* ===== known, but probably not security relevant ===== */
	case 'asp_tags':
	case 'precision':
	case 'assert.bail':
	case 'assert.callback':
	case 'assert.quiet_eval':
	case 'assert.warning':
	case 'auto_detect_line_endings':
	case 'bcmath.scale':
	case 'browscap':
	case 'date.default_latitude':
	case 'date.default_longitude':
	case 'date.sunrise_zenith':
	case 'date.sunset_zenith':
	case 'date.timezone':
	case 'dba.default_handler':
	case 'enable_post_data_reading':
	case 'engine': // can only be 1 here anyway.
	case 'filter.default_flags':
	case 'from':
	case 'gd.jpeg_ignore_warning':
	case 'html_errors':
	case 'ignore_repeated_errors':
	case 'ignore_repeated_source':
	case 'ignore_user_abort':
	case 'implicit_flush':
	case 'suhosin.apc_bug_workaround':
	case 'suhosin.cookie.checkraddr':
	case 'suhosin.cookie.cryptdocroot':
	case 'suhosin.cookie.cryptlist':
	case 'suhosin.cookie.cryptraddr':
	case 'suhosin.cookie.cryptua':
	case 'suhosin.log.syslog.facility':
	case 'suhosin.log.syslog.priority':
	case 'suhosin.log.sapi':
	case 'suhosin.log.script':
	case 'suhosin.log.use-x-forwarded-for':
	case 'suhosin.request.disallow_ws':
		list($result, $reason) = array(TEST_OK, "any value is ok");
		break;
	
	/* ===== unknown / ignored ===== */
	default:
		list($result, $reason) = array(TEST_UNKNOWN, "unknown / not checked.");
		// echo "unknown ini: $k =  $v\n";
	}
	
	if ($result === NULL) {
		tres($meta, TEST_OK);
	} elseif ($result === TEST_SKIPPED) {
		tres($meta, $result, $reason);
	} else {
		tres($meta, $result, $reason, $recommendation);
	}
}

// --- other checks ---

// old version of this script?
if (version_compare(PHP_VERSION, '5.1.0') >= 0) {
	date_default_timezone_set("UTC"); // avoid incorrect timezone warnings in strtotime()
}
if (stripos($pcc_version, "-dev") !== FALSE || stripos($pcc_version, "-rc") !== FALSE) {
	if (time() > strtotime($pcc_date) + (24*3600*60)) { $cfg['need_update'] = 1; }
} elseif (time() > strtotime($pcc_date) + (24*3600*180)) { $cfg['need_update'] = 1; }


// old php version?
$meta = tdesc("PHP Version", "Checks whether your PHP version is < 5.4");
if (version_compare(PHP_VERSION, '5.4.0') >= 0) {
	tres($meta, TEST_OK, "PHP version = " . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION);
} else {
	tres($meta, TEST_HIGH, "PHP version is older than 5.4",
		"Please upgrade PHP as soon as possible. " .
		"Old versions of PHP are not maintained anymore and may contain security flaws.");
}


// suhosin installed?
$meta = tdesc("Suhosin", "Checks whether the Suhosin-Extension is loaded");
if (extension_loaded("suhosin")) {
	tres($meta, TEST_OK);
} else {
	tres($meta, TEST_MAYBE, "Suhosin extension is not loaded", "Suhosin is an advanced protection system for PHP. It is designed to protect servers and users from known and unknown flaws in PHP applications and the PHP core. For more information see http://suhosin.org/");
}


// error_log outside document root?
$meta = tdesc("Error log in document root", "Checks if error_log path is in the current document root");
if ($cfg['is_cli']) { tres($meta, TEST_SKIPPED, "CLI"); }
elseif (ini_get('error_log') === "") { tres($meta, TEST_SKIPPED, "error_log not set."); }
elseif (ini_get('error_log') === "syslog") { tres($meta, TEST_SKIPPED, "error_log to syslog."); }
elseif (!isset($_SERVER['DOCUMENT_ROOT'])) { tres($meta, TEST_SKIPPED, "DOCUMENT_ROOT not set."); }
else {
	$error_log_realpath = realpath(ini_get('error_log'));
	$document_root_realpath = realpath($_SERVER['DOCUMENT_ROOT']);
	if ($error_log_realpath === FALSE) { /* maybe new/nonexistent file? => use dirname instead */
		$error_log_realpath = realpath(dirname(ini_get('error_log')));
	}
	if ($error_log_realpath === FALSE) { tres($meta, TEST_SKIPPED, "error_log invalid or relative path."); }
	elseif ($document_root_realpath === FALSE) { tres($meta, TEST_SKIPPED, "DOCUMENT_ROOT invalid or relative path."); }
	elseif (strncmp($error_log_realpath . DIRECTORY_SEPARATOR, $document_root_realpath . DIRECTORY_SEPARATOR, $document_root_realpath +1) === 0) {
		tres($meta, TEST_HIGH, "error_log in DOCUMENT_ROOT.", "The error logfile is located inside the document root directory and may be accessible publicly. The error_log should always point to a file outside the document root.");
	} else { tres($meta, TEST_OK, "error_log outside of DOCUMENT_ROOT."); }
}


// writable document root?
$meta = tdesc("Writable document root", "Checks if the current document root is writable");
if (!isset($_SERVER['DOCUMENT_ROOT'])) { tres($meta, TEST_SKIPPED, "DOCUMENT_ROOT not set."); }
elseif (is_writable($_SERVER['DOCUMENT_ROOT'])) {
	tres($meta, TEST_HIGH, "document root is writable.", "Making the document root writable may give an attacker the advantage of persisting an exploit. It is probably best to restrict write access to the document root and its subdirectories. Temporary files your application may need to write can be safely stored outside the document root.");
} elseif (is_writable_or_chmodable($_SERVER['DOCUMENT_ROOT'])) {
	tres($meta, TEST_MEDIUM, "document root is potentially writable.", "The document root's access permissions prevent write access, but the current user has the right to change these permissions. Please change the directory's owner.");
} else {
	tres($meta, TEST_OK, "document root not writable.");
}


/*****************************************************************************/


// output
if ($cfg['output_type'] == "text") {
	echo $cfg['s1_logo_aa'] . "\n\n";
	if ($cfg['need_update']) { echo "[*] This script is rather old. Please check for updates:\n    $pcc_url\n\n"; }
	foreach ($all_result_codes as $sev) {
		if (!$cfg['showall'] && !in_array($sev, $cfg['result_codes_default'], true)) { continue; }
		if (!isset($trbs[$sev]) || !$trbs[$sev]) {continue;}
		foreach ($trbs[$sev] as $res) {
			echo sprintf("[%-8s] %s\n", $res['result'], $res['name']);
			echo "  " . $res['reason'] . "\n  " . $res['recommendation'] . "\n";
		}
	}


} elseif ($cfg['output_type'] == "html") {
	function e($str) { return htmlentities($str, ENT_QUOTES); }


?>
<html>
<head><title><?php echo $pcc_name; ?></title>
<style>
body {
	background-color: #fe9;
	color: #111;
	font-family: sans-serif;
}
body, tr, td, table, pre, div {
	font-size: 12px;
}
.<?php echo TEST_CRITICAL; ?> { background-color: #f0c; }
.<?php echo TEST_HIGH; ?>     { background-color: #f00; }
.<?php echo TEST_MEDIUM; ?>   { background-color: #fa0; }
.<?php echo TEST_LOW; ?>      { background-color: #ff0; }
.<?php echo TEST_MAYBE; ?>    { background-color: #1cc; }
.<?php echo TEST_COMMENT; ?>  { background-color: #fff; }
.<?php echo TEST_OK; ?>       { background-color: #0f0; }
.<?php echo TEST_SKIPPED; ?>  { background-color: #888; }
.<?php echo TEST_UNKNOWN; ?>  { background-color: #a50; }
.c {
	text-align: center;
}
td {
	vertical-align: top;
	border: 1px solid black;
	padding: 3px;
}
a:link {color: #0000a9; text-decoration: none;}
a:hover {text-decoration: underline;}
table {border-collapse: collapse;}
.t {
	width: 700px;
	margin-left: auto; margin-right: auto;
	text-align: left;
	margin-bottom: 10px;
}
.t1 {
	background-color: #fff;
}
img {
	float: right;
	border: 0px;
}
</style>
</head>
<body>
<div class="c">
	<table class="t t1">
		<tr><td>
			<a href="https://sektioneins.de/"><img src="<?php echo $cfg['s1_logo']; ?>" width="120px"/></a>
			<?php echo $pcc_name;?><br/>Version <?php echo $pcc_version;?><br/><?php echo $pcc_copy; ?>
		</td></tr>
	</table>
	<?php if ($cfg['need_update']): ?>
		<table class="t"><tr><td class="critical">[*] This script is rather old. Please check for updates: <a href="<?php echo $pcc_url; ?>"><?php echo $pcc_url; ?></a></td></tr></table>
	<?php endif ?>
	<table class="t"><tr>
	<?php
	foreach ($all_result_codes as $sev) {
		if (!$cfg['showall'] && !in_array($sev, $cfg['result_codes_default'], true)) { continue; }
		if (!isset($trbs[$sev])) {continue;}
	?>
		<td class="<?php echo $sev; ?>"><?php echo $sev; ?>: <?php echo count($trbs[$sev]); ?></td>
	<?php
	}
	?></tr></table>

	<table class="t">
	<tr>
		<th>Risk</th>
		<th>Name / Description</th>
		<th>Reason</th>
		<th>Recommendation</th>
	</tr>
	<?php
	foreach ($all_result_codes as $sev) {
		if (!$cfg['showall'] && !in_array($sev, $cfg['result_codes_default'], true)) { continue; }
		if (!isset($trbs[$sev]) || !$trbs[$sev]) {continue;}
		foreach ($trbs[$sev] as $res): ?>
		<tr class="<?php echo $res['result']; ?>">
			<td><?php echo $res['result']; ?></td>
			<td><?php echo e($res['name']); ?><?php if ($res['desc'] !== NULL) {echo "<br/>" . e($res['desc']);} ?></td>
			<td><?php echo e($res['reason']); ?></td>
			<td><?php echo e($res['recommendation']); ?></td>
		</tr>
		<?php endforeach;
	}
	?>
	</table>
</div>
</body>
</html>


<?php
}
?>
