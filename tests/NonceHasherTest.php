<?php

namespace Wordpress\Nonce\Test;

use Wordpress\Nonce\NonceHasher;
use PHPUnit\Framework\TestCase;

class NonceHasherTest extends TestCase {

    public function test__construct() {
        $mock_user     = new \stdClass();
        $mock_user->ID = 2;
        $mock_token    = "h324abc4";

        $cases = [
            [
                "hasher"   => new NonceHasher( "test" ),
                "action"   => "test",
                "lifetime" => DAY_IN_SECONDS,
                "user"     => wp_get_current_user(),
                "token"    => wp_get_session_token()
            ],
            [
                "hasher"   => new NonceHasher( "test", 20 ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => wp_get_current_user(),
                "token"    => wp_get_session_token()
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => $mock_user,
                "token"    => wp_get_session_token()
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

        foreach ( $cases as $n => $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                $this->assertAttributeEquals( $case["lifetime"],
                    "lifetime", $case["hasher"],
                    sprintf( "Case #%d: Lifetime not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["action"],
                    "action", $case["hasher"],
                    sprintf( "Case #%d: Action not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["user"],
                    "user", $case["hasher"],
                    sprintf( "Case #%d: User not equal.", $n + 1 ) );

                $this->assertAttributeEquals( $case["token"],
                    "token", $case["hasher"],
                    sprintf( "Case #%d: Token not equal.", $n + 1 ) );
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
                "hasher"  => new NonceHasher( "test" ),
                "closure" => null,
                "tick"    => 1,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => wp_get_current_user()->ID,
            ],
            [
                "hasher"  => new NonceHasher( "test" ),
                "closure" => null,
                "tick"    => 2,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => wp_get_current_user()->ID,
            ],
            [
                "hasher"  => new NonceHasher( "another-test" ),
                "closure" => null,
                "tick"    => 2,
                "action"  => 'another-test',
                "token"   => wp_get_session_token(),
                "uid"     => wp_get_current_user()->ID,
            ],
            [
                "hasher"  => new NonceHasher( "test" ),
                "closure" => $closure,
                "tick"    => 1,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => wp_get_current_user()->ID + 1,
            ],
            [
                "hasher"  => new NonceHasher( "test", 20, $mock_user ),
                "closure" => null,
                "tick"    => 1,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => $mock_user->ID,
            ],
            [
                "hasher"  => new NonceHasher( "test", 20, $mock_user ),
                "closure" => null,
                "tick"    => 2,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => $mock_user->ID,
            ],
            [
                "hasher"  => new NonceHasher( "test", 20, $mock_user ),
                "closure" => $closure,
                "tick"    => 1,
                "action"  => 'test',
                "token"   => wp_get_session_token(),
                "uid"     => $mock_user->ID,
            ],
        ];

        foreach ( $cases as $n => $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                $hash = self::accessibleHash( $case["hasher"] );
                if ( $hash === false ) {
                    $this->fail( "Unable to get a reference to hash() method." );

                    return;
                }

                if ( ! is_null( $case["closure"] ) ) {
                    add_filter( "nonce_user_logged_out", $case["closure"] );
                }

                $expected = substr(
                    wp_hash( $case['tick'] . '|' . $case['action'] . '|' .
                             $case['uid'] . '|' . $case['token'],
                        'nonce' ),
                    - 12, 10
                );

                $this->assertEquals( $expected, $hash( $case["tick"] ),
                    sprintf( "Case #%d: Hash result not equal.", $n + 1 ) );

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

        $cases = [
            [
                "hasher"   => new NonceHasher( "test" ),
                "action"   => "test",
                "lifetime" => DAY_IN_SECONDS,
                "user"     => wp_get_current_user(),
                "token"    => wp_get_session_token()
            ],
            [
                "hasher"   => new NonceHasher( "test", 20 ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => wp_get_current_user(),
                "token"    => wp_get_session_token()
            ],
            [
                "hasher"   => new NonceHasher( "test", 20, $mock_user ),
                "action"   => "test",
                "lifetime" => 20,
                "user"     => $mock_user,
                "token"    => wp_get_session_token()
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


        foreach ( $cases as $n => $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                $this->assertEquals( $case["lifetime"],
                    $case["hasher"]->getLifetime(),
                    sprintf( "Case #%d: Lifetime not equal.", $n + 1 ) );

                $this->assertEquals( $case["action"],
                    $case["hasher"]->getAction(),
                    sprintf( "Case #%d: Action not equal.", $n + 1 ) );

                $this->assertEquals( $case["user"],
                    $case["hasher"]->getUser(),
                    sprintf( "Case #%d: User not equal.", $n + 1 ) );

                $this->assertEquals( $case["token"],
                    $case["hasher"]->getToken(),
                    sprintf( "Case #%d: Token not equal.", $n + 1 ) );
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

        foreach ( $cases as $n => $case ) {
            if ( $case["hasher"] instanceof NonceHasher ) {
                if ( ! is_null( $case["closure"] ) ) {
                    add_filter( "nonce_life", $case["closure"] );
                }

                $expected = ceil( time() / ( $case["lifetime"] / 2 ) );
                $this->assertEquals( $expected, $case["hasher"]->tick(),
                    sprintf( "Case #%d: Tick result is not equal.", $n + 1 ) );

                if ( ! is_null( $case["closure"] ) ) {
                    remove_filter( "nonce_life", $case["closure"] );
                }
            }
        }
    }
}
