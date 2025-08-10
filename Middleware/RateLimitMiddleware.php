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
 * @since         5.3.0
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 */
namespace Cake\Http\Middleware;

use Cake\Cache\Cache;
use Cake\Http\Exception\TooManyRequestsException;
use Cake\Http\RateLimit\FixedWindowRateLimiter;
use Cake\Http\RateLimit\RateLimiterInterface;
use Cake\Http\RateLimit\SlidingWindowRateLimiter;
use Cake\Http\RateLimit\TokenBucketRateLimiter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Rate limiting middleware
 *
 * Provides configurable rate limiting based on various identifiers.
 * Supports multiple strategies including sliding window, token bucket, and fixed window.
 */
class RateLimitMiddleware implements MiddlewareInterface
{
    /**
     * Default configuration
     *
     * @var array<string, mixed>
     */
    protected array $defaultConfig = [
        'limit' => 60,
        'window' => 60,
        'identifier' => 'ip',
        'strategy' => 'sliding_window',
        'cache' => 'default',
        'headers' => true,
        'message' => 'Rate limit exceeded. Please try again later.',
        'skipCheck' => null,
        'costCallback' => null,
        'identifierCallback' => null,
        'limitCallback' => null,
    ];

    /**
     * Configuration
     *
     * @var array<string, mixed>
     */
    protected array $config;

    /**
     * Constructor
     *
     * @param array<string, mixed> $config Configuration options
     */
    public function __construct(array $config = [])
    {
        $this->config = $config + $this->defaultConfig;
    }

    /**
     * Process the request and add rate limiting
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @param \Psr\Http\Server\RequestHandlerInterface $handler The handler
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->shouldSkip($request)) {
            return $handler->handle($request);
        }

        $identifier = $this->getIdentifier($request);
        $limit = $this->getLimit($request, $identifier);
        $window = $this->config['window'];
        $cost = $this->getCost($request);

        $rateLimiter = $this->getRateLimiter();
        $result = $rateLimiter->attempt($identifier, $limit, $window, $cost);

        if (!$result['allowed']) {
            throw new TooManyRequestsException($this->config['message']);
        }

        $response = $handler->handle($request);

        if ($this->config['headers']) {
            $response = $this->addRateLimitHeaders($response, $result);
        }

        return $response;
    }

    /**
     * Check if rate limiting should be skipped for this request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return bool
     */
    protected function shouldSkip(ServerRequestInterface $request): bool
    {
        if ($this->config['skipCheck'] === null) {
            return false;
        }

        return (bool)call_user_func($this->config['skipCheck'], $request);
    }

    /**
     * Get the identifier for rate limiting
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return string
     */
    protected function getIdentifier(ServerRequestInterface $request): string
    {
        if ($this->config['identifierCallback'] !== null) {
            return (string)call_user_func($this->config['identifierCallback'], $request);
        }

        return match ($this->config['identifier']) {
            'ip' => $this->getClientIp($request),
            'user' => $this->getUserIdentifier($request),
            'route' => $this->getRouteIdentifier($request),
            'api_key' => $this->getApiKeyIdentifier($request),
            default => $this->getClientIp($request),
        };
    }

    /**
     * Get client IP address
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return string
     */
    protected function getClientIp(ServerRequestInterface $request): string
    {
        $params = $request->getServerParams();

        if (!empty($params['HTTP_CF_CONNECTING_IP'])) {
            return $params['HTTP_CF_CONNECTING_IP'];
        }

        if (!empty($params['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $params['HTTP_X_FORWARDED_FOR']);

            return trim($ips[0]);
        }

        if (!empty($params['HTTP_X_REAL_IP'])) {
            return $params['HTTP_X_REAL_IP'];
        }

        return $params['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Get user identifier
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return string
     */
    protected function getUserIdentifier(ServerRequestInterface $request): string
    {
        $user = $request->getAttribute('identity');
        if ($user) {
            if (method_exists($user, 'getIdentifier')) {
                return 'user_' . $user->getIdentifier();
            } elseif (isset($user->id)) {
                return 'user_' . $user->id;
            }
        }

        return $this->getClientIp($request);
    }

    /**
     * Get route identifier
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return string
     */
    protected function getRouteIdentifier(ServerRequestInterface $request): string
    {
        $params = $request->getAttribute('params', []);
        $route = sprintf(
            '%s::%s.%s',
            $params['plugin'] ?? 'app',
            $params['controller'] ?? 'unknown',
            $params['action'] ?? 'unknown',
        );

        return $route . '_' . $this->getClientIp($request);
    }

    /**
     * Get API key identifier
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return string
     */
    protected function getApiKeyIdentifier(ServerRequestInterface $request): string
    {
        $apiKey = $request->getHeaderLine('X-API-Key');
        if (empty($apiKey)) {
            $apiKey = $request->getQuery('api_key', '');
        }

        return !empty($apiKey) ? 'api_' . $apiKey : $this->getClientIp($request);
    }

    /**
     * Get rate limit for the request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @param string $identifier The identifier
     * @return int
     */
    protected function getLimit(ServerRequestInterface $request, string $identifier): int
    {
        if ($this->config['limitCallback'] !== null) {
            return (int)call_user_func($this->config['limitCallback'], $request, $identifier);
        }

        return (int)$this->config['limit'];
    }

    /**
     * Get the cost of the request
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @return int
     */
    protected function getCost(ServerRequestInterface $request): int
    {
        if ($this->config['costCallback'] !== null) {
            return (int)call_user_func($this->config['costCallback'], $request);
        }

        return 1;
    }

    /**
     * Get rate limiter instance based on strategy
     *
     * @return \Cake\Http\RateLimit\RateLimiterInterface
     */
    protected function getRateLimiter(): RateLimiterInterface
    {
        $cache = Cache::pool($this->config['cache']);

        return match ($this->config['strategy']) {
            'token_bucket' => new TokenBucketRateLimiter($cache),
            'fixed_window' => new FixedWindowRateLimiter($cache),
            'sliding_window' => new SlidingWindowRateLimiter($cache),
            default => new SlidingWindowRateLimiter($cache),
        };
    }

    /**
     * Add rate limit headers to response
     *
     * @param \Psr\Http\Message\ResponseInterface $response The response
     * @param array<string, mixed> $result Rate limit result
     * @return \Psr\Http\Message\ResponseInterface
     */
    protected function addRateLimitHeaders(ResponseInterface $response, array $result): ResponseInterface
    {
        return $response
            ->withHeader('X-RateLimit-Limit', (string)$result['limit'])
            ->withHeader('X-RateLimit-Remaining', (string)$result['remaining'])
            ->withHeader('X-RateLimit-Reset', (string)$result['reset'])
            ->withHeader('X-RateLimit-Reset-Date', date('c', $result['reset']));
    }
}
