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
            if ( $case["hasher"] instanceof NonceHasher ) {
                $this->assertAttributeEquals( $case["lifetime"], "lifetime",
                    $case["hasher"], "Lifetime not equal." );

                $this->assertAttributeEquals( $case["action"], "action",
                    $case["hasher"], "Action not equal." );

                $this->assertAttributeEquals( $case["user"], "user",
                    $case["hasher"], "User not equal." );

                $this->assertAttributeEquals( $case["token"], "token",
                    $case["hasher"], "Token not equal." );
            }
        }
    }

    private static function accessibleHash( $hasher ) {
        try {
            $hash = new \ReflectionMethod(
                'Wordpress\Nonce\NonceHasher', 'hash' );
            $hash->setAccessible( true );

            return function ( $tick ) use ( $hash, $hasher ) {
                return $hash->invokeArgs( $hasher, [ $tick ] );
            };
        } catch ( \ReflectionException $e ) {
            return false;
        }
    }

    public function testHash() {
        $mock_user     = new \stdClass();
        $mock_user->ID = 2;

        $closure = function ( $uid ) {
            return (int) $uid + 1;
        };

        $cases = [
            [
                "hasher"   => new NonceHasher( "test" ),
                "closure"  => null,
                "tick"     => 1,
                "expected" => "390ffd9ed8",
            ],
            [
                "hasher"   => new NonceHasher( "test" ),
                "closure"  => null,
                "tick"     => 2,
                "expected" => "6ee19b817c",
            ],
            [
                "hasher"   => new NonceHasher( "test" ),
                "closure"  => $closure,
                "tick"     => 1,
                "expected" => "bda33ff15b",
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "closure"  => null,
                "tick"     => 1,
                "expected" => "0babebeae1",
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "closure"  => null,
                "tick"     => 2,
                "expected" => "2ae21e13ec",
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "closure"  => $closure,
                "tick"     => 1,
                "expected" => "0babebeae1",
            ],
        ];

        foreach ( $cases as $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                $hash = self::accessibleHash( $case["hasher"] );
                if ( $hash === false ) {
                    $this->fail( "Unable to get a reference to hash() method." );

                    return;
                }

                if ( ! is_null( $case["closure"] ) ) {
                    add_filter( "nonce_user_logged_out", $case["closure"] );
                }

                $this->assertEquals( $case["expected"],
                    $hash( $case["tick"] ), "Hash result not equal." );

                if ( ! is_null( $case["closure"] ) ) {
                    remove_filter( "nonce_user_logged_out", $case["closure"] );
                }
            }
        }
    }

    public function testAccessors() {
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
            if ( $case["hasher"] instanceof NonceHasher ) {
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
    }

    public function testTick() {
        $closure = function () {
            return 10;
        };

        $cases = [
            [
                "hasher"   => new NonceHasher( "test" ),
                "closure"  => null,
                "lifetime" => DAY_IN_SECONDS
            ],
            [
                "hasher"   => new NonceHasher( "test" ),
                "closure"  => $closure,
                "lifetime" => $closure()
            ],
            [
                "hasher"   => new NonceHasher( "test", 20 ),
                "closure"  => null,
                "lifetime" => 20
            ],
            [
                "hasher"   => new NonceHasher( "test", 20 ),
                "closure"  => $closure,
                "lifetime" => $closure()
            ]
        ];

        foreach ( $cases as $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                if ( ! is_null( $case["closure"] ) ) {
                    add_filter( "nonce_life", $case["closure"] );
                }

                $expected = ceil( time() / ( $case["lifetime"] / 2 ) );
                $this->assertEquals( $expected, $case["hasher"]->tick(),
                    "Tick result is not equal." );

                if ( ! is_null( $case["closure"] ) ) {
                    remove_filter( "nonce_life", $case["closure"] );
                }
            }
        }
    }
}
