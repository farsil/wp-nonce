<?php

namespace Wordpress\Nonce;

class NonceGenerator extends NonceHasher {
    public function __construct(
        $action = - 1, $lifetime = DAY_IN_SECONDS,
        $user = null, $token = null
    ) {
        parent::__construct( $action, $lifetime, $user, $token );
    }

    public function generate() {
        return $this->getNonce( $this->tick() );
    }

    public function url( $action_url, $name = "_wpnonce" ) {
        $action_url = str_replace( '&amp;', '&', $action_url );

        return esc_html(
            add_query_arg( $name, $this->generate(), $action_url )
        );
    }

    public function field( $name = "_wpnonce", $referer = true, $echo = true ) {
        $name        = esc_attr( $name );
        $nonce_field = '<input type="hidden" id="' . $name .
                       '" name="' . $name . '" value="' . $this->generate() .
                       '" />';

        if ( $referer ) {
            $nonce_field .= wp_referer_field( false );
        }

        if ( $echo ) {
            echo $nonce_field;
        }

        return $nonce_field;
    }
}
