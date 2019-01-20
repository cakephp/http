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

use Cake\Core\App;
use Cake\Http\Middleware\CallableMiddleware;
use Cake\Http\Middleware\DoublePassMiddleware;
use Closure;
use Countable;
use LogicException;
use Psr\Http\Server\MiddlewareInterface;
use ReflectionFunction;
use RuntimeException;

/**
 * Provides methods for creating and manipulating a "queue" of middleware callables.
 * This queue is used to process a request and response via \Cake\Http\Runner.
 */
class MiddlewareQueue implements Countable
{
    /**
     * The queue of middlewares.
     *
     * @var array
     */
    protected $queue = [];

    /**
     * The queue of middlewares.
     *
     * @var \Psr\Http\Server\MiddlewareInterface[]
     */
    protected $middlewares = [];

    /**
     * Constructor
     *
     * @param array $middleware The list of middleware to append.
     */
    public function __construct(array $middleware = [])
    {
        $this->queue = $middleware;
    }

    /**
     * Get the middleware at the provided index.
     *
     * @param int $index The index to fetch.
     * @return \Psr\Http\Server\MiddlewareInterface|null Either the middleware or null
     *   if the index is undefined.
     */
    public function get(int $index): ?MiddlewareInterface
    {
        if (isset($this->middlewares[$index])) {
            return $this->middlewares[$index];
        }

        return $this->resolve($index);
    }

    /**
     * Resolve middleware name to a PSR 15 compliant middleware instance.
     *
     * @param int $index The index to fetch.
     * @return \Psr\Http\Server\MiddlewareInterface|null Either the middleware or null
     *   if the index is undefined.
     * @throws \RuntimeException If Middleware not found.
     */
    protected function resolve(int $index): ?MiddlewareInterface
    {
        if (!isset($this->queue[$index])) {
            return null;
        }

        $middleware = $this->queue[$index];
        if (is_string($middleware)) {
            $className = App::className($middleware, 'Middleware', 'Middleware');
            if ($className === null || !class_exists($className)) {
                throw new RuntimeException(sprintf(
                    'Middleware "%s" was not found.',
                    $middleware
                ));
            }
            $middleware = new $className();
        }

        if ($middleware instanceof MiddlewareInterface) {
            return $this->middlewares[$index] = $middleware;
        }

        if (!$middleware instanceof Closure) {
            return $this->middlewares[$index] = new DoublePassMiddleware($middleware);
        }

        $info = new ReflectionFunction($middleware);
        if ($info->getNumberOfParameters() > 2) {
            return $this->middlewares[$index] = new DoublePassMiddleware($middleware);
        }

        return $this->middlewares[$index] = new CallableMiddleware($middleware);
    }

    /**
     * Append a middleware to the end of the queue.
     *
     * @param callable|string|array $middleware The middleware(s) to append.
     * @return $this
     */
    public function add($middleware): self
    {
        if (is_array($middleware)) {
            $this->queue = array_merge($this->queue, $middleware);

            return $this;
        }
        $this->queue[] = $middleware;

        return $this;
    }

    /**
     * Alias for MiddlewareQueue::add().
     *
     * @param callable|string|array $middleware The middleware(s) to append.
     * @return $this
     * @see MiddlewareQueue::add()
     */
    public function push($middleware): self
    {
        return $this->add($middleware);
    }

    /**
     * Prepend a middleware to the start of the queue.
     *
     * @param callable|string|array $middleware The middleware(s) to prepend.
     * @return $this
     */
    public function prepend($middleware): self
    {
        if (is_array($middleware)) {
            $this->queue = array_merge($middleware, $this->queue);

            return $this;
        }
        array_unshift($this->queue, $middleware);

        return $this;
    }

    /**
     * Insert a middleware callable at a specific index.
     *
     * If the index already exists, the new callable will be inserted,
     * and the existing element will be shifted one index greater.
     *
     * @param int $index The index to insert at.
     * @param callable|string $middleware The middleware to insert.
     * @return $this
     */
    public function insertAt(int $index, $middleware): self
    {
        array_splice($this->queue, $index, 0, [$middleware]);

        return $this;
    }

    /**
     * Insert a middleware object before the first matching class.
     *
     * Finds the index of the first middleware that matches the provided class,
     * and inserts the supplied callable before it.
     *
     * @param string $class The classname to insert the middleware before.
     * @param callable|string $middleware The middleware to insert.
     * @return $this
     * @throws \LogicException If middleware to insert before is not found.
     */
    public function insertBefore(string $class, $middleware): self
    {
        $found = false;
        $i = null;
        foreach ($this->queue as $i => $object) {
            if ((is_string($object) && $object === $class)
                || is_a($object, $class)
            ) {
                $found = true;
                break;
            }
        }
        if ($found) {
            return $this->insertAt($i, $middleware);
        }
        throw new LogicException(sprintf("No middleware matching '%s' could be found.", $class));
    }

    /**
     * Insert a middleware object after the first matching class.
     *
     * Finds the index of the first middleware that matches the provided class,
     * and inserts the supplied callable after it. If the class is not found,
     * this method will behave like add().
     *
     * @param string $class The classname to insert the middleware before.
     * @param callable|string $middleware The middleware to insert.
     * @return $this
     */
    public function insertAfter(string $class, $middleware): self
    {
        $found = false;
        $i = null;
        foreach ($this->queue as $i => $object) {
            if ((is_string($object) && $object === $class)
                || is_a($object, $class)
            ) {
                $found = true;
                break;
            }
        }
        if ($found) {
            return $this->insertAt($i + 1, $middleware);
        }

        return $this->add($middleware);
    }

    /**
     * Get the number of connected middleware layers.
     *
     * Implement the Countable interface.
     *
     * @return int
     */
    public function count(): int
    {
        return count($this->queue);
    }
}
