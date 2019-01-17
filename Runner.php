<?php
declare(strict_types=1);
/**
 * CakePHP(tm) : Rapid Development Framework (https://cakephp.org)
 * Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright     Copyright (c) Cake Software Foundation, Inc. (https://cakefoundation.org)
 * @link          https://cakephp.org CakePHP(tm) Project
 * @since         3.3.0
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 */
namespace Cake\Http;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Executes the middleware queue and provides the `next` callable
 * that allows the queue to be iterated.
 */
class Runner implements RequestHandlerInterface
{
    /**
     * The current index in the middleware queue.
     *
     * @var int
     */
    protected $index;

    /**
     * The middleware queue being run.
     *
     * @var \Cake\Http\MiddlewareQueue
     */
    protected $queue;

    protected $responsePrototype;

    /**
     * @param \Cake\Http\MiddlewareQueue $queue The middleware queue
     * @param \Psr\Http\Message\ServerRequestInterface $request The Server Request
     * @param \Psr\Http\Message\ResponseInterface $responsePrototype A response object
     * @return \Psr\Http\Message\ResponseInterface A response object
     */
    public function run(
        MiddlewareQueue $queue,
        ServerRequestInterface $request,
        ?ResponseInterface $responsePrototype = null
    ): ResponseInterface {
        $this->queue = $queue;
        $this->index = 0;
        $this->responsePrototype = $responsePrototype ?: (new Response())->withStatus(500);

        return $this->handle($request);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request The server request
     * @return \Psr\Http\Message\ResponseInterface An updated response
     */
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $middleware = $this->queue->get($this->index++);

        if ($middleware === null) {
            return $this->responsePrototype;
        }

        return $middleware->process($request, $this);
    }
}
