<?php

namespace MRBS\Auth;

use MRBS\User;

require_once __DIR__ . '/../../../vendor/autoload.php';

class AuthLdapNmh extends AuthLdap
{
    private function getLdapConnection(): \LdapRecord\Connection
    {
        global $ldap_host;

        return new \LdapRecord\Connection([
            'hosts' => (array) $ldap_host,
        ]);
    }

    private function getDefaultUsername(string $username): string
    {
        $username = trim(strtolower($username));

        return str_starts_with($username, 'apps\\') ? $username : 'apps\\' . $username;
    }

    public function validateUser(
        #[\SensitiveParameter]
        ?string $user,
        #[\SensitiveParameter]
        ?string $pass
    ) {
        $user = $this->getDefaultUsername($user);

        return $this->getLdapConnection()->auth()->attempt($user, $pass) ? $user : false;
    }

    protected function getUserFresh(string $username): ?User
    {
        // $user = $this->getLdapConnection()->query()->where('uid', '=', $username)->first();

        // if (!$user) {
        //     return null;
        // }

        $username = $this->getDefaultUsername($username);

        $user = new User($username);
        $user->display_name = str_replace('apps\\', '', $username);
        $user->level = $this->getDefaultLevel($username);
        $user->email = $this->getDefaultEmail($username);

        return $user;
    }

    public function getUsernames()
    {
        $mrbs_user = session()->getCurrentUser();

        if (!isset($mrbs_user)) {
            return false;
        }

        // $ldap_users = $this->getLdapConnection()->query()->get();

        // if (is_array($ldap_users)) {
        //     $ldap_users = new Collection($ldap_users);
        // }

        // return $ldap_users->map(function ($user) {
        //     return [
        //         'username' => $user->uid,
        //         'display_name' => $user->cn,
        //     ];
        // })->toArray();

        return [];
    }

    // Gets the level from the $auth['admin'] array in the config file
    protected function getDefaultLevel(?string $username): int
    {
        global $auth, $max_level;

        // User not logged in, user level '0'
        if (!isset($username)) {
            return 0;
        }

        // Check whether the user is an admin; if not they are level 1.
        return (isset($auth['admin']) && in_array($username, $auth['admin'])) ? $max_level : 1;
    }


    // Gets the default email address using config file settings
    protected function getDefaultEmail(?string $username): string
    {
        global $mail_settings;

        if (!isset($username) || $username === '') {
            return '';
        }

        $email = $username;

        // Remove the suffix, if there is one
        if (isset($mail_settings['username_suffix']) && ($mail_settings['username_suffix'] !== '')) {
            $suffix = $mail_settings['username_suffix'];
            if (substr($email, -strlen($suffix)) === $suffix) {
                $email = substr($email, 0, -strlen($suffix));
            }
        }

        // Add on the domain, if there is one
        if (isset($mail_settings['domain']) && ($mail_settings['domain'] !== '')) {
            // Trim any leading '@' character. Older versions of MRBS required the '@' character
            // to be included in $mail_settings['domain'], and we still allow this for backwards
            // compatibility.
            $domain = ltrim($mail_settings['domain'], '@');
            $email .= '@' . $domain;
        }

        return $email;
    }
}
