<?php
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

use Cake\Core\ConsoleApplicationInterface;
use Cake\Core\HttpApplicationInterface;
use Cake\Core\PluginRegistry;
use Cake\Core\PluginRegistryInterface;
use Cake\Routing\DispatcherFactory;
use Cake\Routing\Router;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Base class for application classes.
 *
 * The application class is responsible for bootstrapping the application,
 * and ensuring that middleware is attached. It is also invoked as the last piece
 * of middleware, and delegates request/response handling to the correct controller.
 */
abstract class BaseApplication implements ConsoleApplicationInterface, HttpApplicationInterface
{

    /**
     * @var string Contains the path of the config directory
     */
    protected $configDir;

    /**
     * Plugin Registry
     *
     * @param \Cake\Core\PluginRegistry
     */
    protected $pluginRegistry;

    /**
     * Default Plugin Registry Class
     *
     * @var string
     */
    protected $defaultPluginRegistry = PluginRegistry::class;

    /**
     * Constructor
     *
     * @param string $configDir The directory the bootstrap configuration is held in.
     * @param string|null $pluginRegistry Plugin Registry Object
     */
    public function __construct($configDir, $pluginRegistry = null)
    {
        $this->configDir = $configDir;

        $this->setPluginRegistry($pluginRegistry);
    }

    /**
     * Sets the plugin registry
     *
     * @param string|null $pluginRegistry Plugin Registry Object
     * @return void
     */
    public function setPluginRegistry($pluginRegistry = null)
    {
        if (empty($pluginRegistry)) {
            $this->pluginRegistry = new $this->defaultPluginRegistry();

            return;
        }

        if (!$pluginRegistry instanceof PluginRegistryInterface) {
            throw new InvalidArgumentException(sprintf(
                '`%s` is not an instance of `%s`',
                get_class($pluginRegistry),
                PluginRegistryInterface::class
            ));
        }

        $this->pluginRegistry = $pluginRegistry;
    }

    /**
     * @param \Cake\Http\MiddlewareQueue $middleware The middleware queue to set in your App Class
     * @return \Cake\Http\MiddlewareQueue
     */
    abstract public function middleware($middleware);

    /**
     * {@inheritDoc}
     */
    public function bootstrap()
    {
        require_once $this->configDir . '/bootstrap.php';

        $this->pluginRegistry()->bootstrap();
    }

    /**
     * {@inheritDoc}
     *
     * By default this will load `config/routes.php` for ease of use and backwards compatibility.
     *
     * @param \Cake\Routing\RouteBuilder $routes A route builder to add routes into.
     * @return void
     */
    public function routes($routes)
    {
        if (!Router::$initialized) {
            require $this->configDir . '/routes.php';
            // Prevent routes from being loaded again

            $this->pluginRegistry()->routes($routes);
            Router::$initialized = true;
        }
    }

    /**
     * Define the console commands for an application.
     *
     * By default all commands in CakePHP, plugins and the application will be
     * loaded using conventions based names.
     *
     * @param \Cake\Console\CommandCollection $commands The CommandCollection to add commands into.
     * @return \Cake\Console\CommandCollection The updated collection.
     */
    public function console($commands)
    {
        $commands->addMany($commands->autoDiscover());

        return $this->pluginRegistry()->console($commands);
    }

    /**
     * Invoke the application.
     *
     * - Convert the PSR response into CakePHP equivalents.
     * - Create the controller that will handle this request.
     * - Invoke the controller.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request
     * @param \Psr\Http\Message\ResponseInterface $response The response
     * @param callable $next The next middleware
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        return $this->getDispatcher()->dispatch($request, $response);
    }

    /**
     * Get the ActionDispatcher.
     *
     * @return \Cake\Http\ActionDispatcher
     */
    protected function getDispatcher()
    {
        return new ActionDispatcher(null, null, DispatcherFactory::filters());
    }

    /**
     * Plugins
     *
     * @return \Cake\Core\PluginRegistry
     */
    public function pluginRegistry()
    {
        return $this->pluginRegistry;
    }
}
