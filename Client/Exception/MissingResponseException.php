<?php
declare(strict_types=1);

/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link          https://cakephp.org CakePHP(tm) Project
 * @since         4.3.0
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 */
namespace Cake\Http\Client\Exception;

use RuntimeException;

/**
 * Used to indicate that a request did not have a matching mock response.
 */
class MissingResponseException extends RuntimeException
{
    /**
     * Constructor
     *
     * @param string $method The HTTP method used.
     * @param string $url The request URL.
     */
    public function __construct(string $method, string $url)
    {
        $message = "Unable to find a mocked response for {$method} to {$url}.";
        parent::__construct($message);
    }
}
