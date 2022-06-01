<?php

namespace App\Helpers;

use Mautic\Auth\ApiAuth;

/**
 * Class MauticHelper
 * @package App\Helpers
 */
class MauticHelper
{
    /**
     * @var string
     */
    private static $instance;

    /**
     * @return MauticHelper
     */
    public static function getInstance()
    {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * @return array|\Mautic\Auth\AuthInterface
     */
    public function pushLeadToStackk()
    {
        try {
            session_start();
            $settings = [
                'AuthMethod'    => 'BasicAuth',
                'userName'      => 'test@mail.com',      // Create a new user
                'password'      => 'Test@123', // Make it a secure password
            ];
            // Initiate the auth object specifying to use BasicAuth
            $initAuth   = new ApiAuth();
            $auth       = $initAuth->newAuth($settings, 'BasicAuth');

            return $auth;
        } catch (\Exception $e) {
            return $e->getMessage();
        }
    }
}
