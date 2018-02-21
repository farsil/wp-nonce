<?php

namespace Wordpress\Nonce;

use Throwable;

class AuthException extends \Exception {
    private $action;

    public function __construct(
        string $action, string $message = "",
        int $code = 0, Throwable $previous = null
    ) {
        parent::__construct( $message, $code, $previous );
        $this->action = $action;
    }

    /**
     * @return string
     */
    public function getAction(): string {
        return $this->action;
    }
}