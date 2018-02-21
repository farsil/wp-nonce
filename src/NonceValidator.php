<?php

namespace Wordpress\Nonce;

class NonceValidator extends NonceHasher {
    public function __construct(
        $action, $lifetime = DAY_IN_SECONDS,
        $user = null, $token = null
    ) {
        parent::__construct( $action, $lifetime, $user, $token );
    }

    /**
     * @throws AuthException
     */
    public function checkAdminReferer( $query_arg = "_wpnonce" ) {
        $admin_url = strtolower( admin_url() );
        $referer   = strtolower( wp_get_referer() );

        $result = isset( $_REQUEST[ $query_arg ] ) ?
            $this->verify( $_REQUEST[ $query_arg ] ) : false;

        do_action( 'check_admin_referer', $this->getAction(), $result );

        if ( ! $result && strpos( $referer, $admin_url ) !== 0 ) {
            throw new AuthException( $this->getAction(),
                "Referer does not come from an admin URL."
            );
        }

        return $result;
    }

    public function verify( $nonce ) {
        $nonce = (string) $nonce;
        if ( empty( $nonce ) ) {
            return false;
        }

        $tick = $this->tick();
        if ( hash_equals( $this->getNonce( $tick ), $nonce ) ) {
            return 1;
        }
        if ( hash_equals( $this->getNonce( $tick - 1 ), $nonce ) ) {
            return 2;
        }

        do_action(
            'wp_verify_nonce_failed',
            $nonce, $this->getAction(), $this->getUser(), $this->getToken()
        );

        return false;
    }

    public function checkAjaxReferer( $query_arg = false ) {
        $nonce = '';

        if ( $query_arg && isset( $_REQUEST[ $query_arg ] ) ) {
            $nonce = $_REQUEST[ $query_arg ];
        } elseif ( isset( $_REQUEST['_ajax_nonce'] ) ) {
            $nonce = $_REQUEST['_ajax_nonce'];
        } elseif ( isset( $_REQUEST['_wpnonce'] ) ) {
            $nonce = $_REQUEST['_wpnonce'];
        }

        $result = $this->verify( $nonce );
        do_action( 'check_ajax_referer', $this->getAction(), $result );

        return $result;
    }
}
