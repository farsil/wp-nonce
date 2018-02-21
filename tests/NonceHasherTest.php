<?php

namespace Wordpress\Nonce\Test;

use Wordpress\Nonce\NonceHasher;
use PHPUnit\Framework\TestCase;

class NonceHasherTest extends TestCase {

    public function test__construct() {
        $mock_user     = new \stdClass();
        $mock_user->ID = 2;
        $mock_token    = "h324abc4";

        $current_user  = wp_get_current_user();
        $session_token = wp_get_session_token();

        $cases = [
            [
                "hasher"   => new NonceHasher( "test" ),
                "action"   => "test",
                "lifetime" => DAY_IN_SECONDS,
                "user"     => $current_user,
                "token"    => $session_token
            ],
            [
                "hasher"   => new NonceHasher( "test", 20 ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => $current_user,
                "token"    => $session_token
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => $mock_user,
                "token"    => $session_token
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user,
                    $mock_token ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => $mock_user,
                "token"    => $mock_token
            ],
        ];

        foreach ( $cases as $case ) {
            $this->assertEquals( $case["lifetime"],
                $case["hasher"]->getLifetime(), "Lifetime not equal." );

            $this->assertEquals( $case["action"],
                $case["hasher"]->getAction(), "Action not equal." );

            $this->assertEquals( $case["user"],
                $case["hasher"]->getUser(), "User not equal." );

            $this->assertEquals( $case["token"],
                $case["hasher"]->getToken(), "Token not equal." );
        }
    }

    public function testTick() {
        $closure = function () {
            return 10;
        };

        $cases = [
            [
                "hasher"  => new NonceHasher( "test" ),
                "closure" => null
            ],
            [
                "hasher"  => new NonceHasher( "test" ),
                "closure" => $closure
            ],
            [
                "hasher"  => new NonceHasher( "test", 20 ),
                "closure" => null
            ],
            [
                "hasher"  => new NonceHasher( "test", 20 ),
                "closure" => $closure
            ]
        ];

        foreach ( $cases as $case ) {
            if ( is_null( $case["closure"] ) ) {
                $lifetime = $case["hasher"]->getLifetime();
            } else {
                $lifetime = $case["closure"]();
                add_filter( "nonce_life", $case["closure"] );
            }

            $expected = ceil( time() / ( $lifetime / 2 ) );
            $this->assertEquals( $expected, $case["hasher"]->tick(),
                "Tick is not equal." );

            if ( ! is_null( $case["closure"] ) ) {
                remove_filter( "nonce_life", $case["closure"] );
            }
        }
    }
}
