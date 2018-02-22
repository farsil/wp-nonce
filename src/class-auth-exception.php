<?php

namespace Wordpress;

use Throwable;

/**
 * Class Auth_Exception. Thrown when user does not have the necessary
 * permissions to do something.
 * @package Wordpress
 */
class Auth_Exception extends \Exception {
    /**
     * The action used for the cryptographic nonce.
     * @var string
     */
    private $action;

    /**
     * Auth_Exception constructor.
     *
     * @param string|int $action The action used for the cryptographic nonce.
     * @param string $message [optional] The Exception message to throw.
     * @param int $code [optional] The Exception code.
     * @param Throwable $previous [optional] The previous throwable used for
     * the exception chaining.
     */
    public function __construct(
        $action, string $message = '',
        int $code = 0, Throwable $previous = null
    ) {
        parent::__construct( $message, $code, $previous );
        $this->action = $action;
    }

    /**
     * Returns the value used to add context to the nonces.
     *
     * @return string|int The action.
     */
    public function get_action() {
        return $this->action;
    }
}