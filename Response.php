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
 * @since         2.0.0
 * @license       https://opensource.org/licenses/mit-license.php MIT License
 */
namespace Cake\Http;

use Cake\Core\Configure;
use Cake\Filesystem\File;
use Cake\Filesystem\Folder;
use Cake\Http\Cookie\Cookie;
use Cake\Http\Cookie\CookieCollection;
use Cake\Http\Cookie\CookieInterface;
use Cake\Http\CorsBuilder;
use Cake\Http\Exception\NotFoundException;
use Cake\Log\Log;
use DateTime;
use DateTimeZone;
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Zend\Diactoros\MessageTrait;
use Zend\Diactoros\Stream;

/**
 * Responses contain the response text, status and headers of a HTTP response.
 */
class Response implements ResponseInterface
{

    use MessageTrait;

    /**
     * Holds HTTP response statuses
     *
     * @var array
     */
    protected $_statusCodes = [
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-status',
        208 => 'Already Reported',
        226 => 'IM used',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        306 => '(Unused)',
        307 => 'Temporary Redirect',
        308 => 'Permanent Redirect',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Large',
        415 => 'Unsupported Media Type',
        416 => 'Requested range not satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',
        421 => 'Misdirected Request',
        422 => 'Unprocessable Entity',
        423 => 'Locked',
        424 => 'Failed Dependency',
        425 => 'Unordered Collection',
        426 => 'Upgrade Required',
        428 => 'Precondition Required',
        429 => 'Too Many Requests',
        431 => 'Request Header Fields Too Large',
        444 => 'Connection Closed Without Response',
        451 => 'Unavailable For Legal Reasons',
        499 => 'Client Closed Request',
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'Unsupported Version',
        506 => 'Variant Also Negotiates',
        507 => 'Insufficient Storage',
        508 => 'Loop Detected',
        510 => 'Not Extended',
        511 => 'Network Authentication Required',
        599 => 'Network Connect Timeout Error',
    ];

    /**
     * Holds type key to mime type mappings for known mime types.
     *
     * @var array
     */
    protected $_mimeTypes = [
        'html' => ['text/html', '*/*'],
        'json' => 'application/json',
        'xml' => ['application/xml', 'text/xml'],
        'xhtml' => ['application/xhtml+xml', 'application/xhtml', 'text/xhtml'],
        'webp' => 'image/webp',
        'rss' => 'application/rss+xml',
        'ai' => 'application/postscript',
        'bcpio' => 'application/x-bcpio',
        'bin' => 'application/octet-stream',
        'ccad' => 'application/clariscad',
        'cdf' => 'application/x-netcdf',
        'class' => 'application/octet-stream',
        'cpio' => 'application/x-cpio',
        'cpt' => 'application/mac-compactpro',
        'csh' => 'application/x-csh',
        'csv' => ['text/csv', 'application/vnd.ms-excel'],
        'dcr' => 'application/x-director',
        'dir' => 'application/x-director',
        'dms' => 'application/octet-stream',
        'doc' => 'application/msword',
        'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'drw' => 'application/drafting',
        'dvi' => 'application/x-dvi',
        'dwg' => 'application/acad',
        'dxf' => 'application/dxf',
        'dxr' => 'application/x-director',
        'eot' => 'application/vnd.ms-fontobject',
        'eps' => 'application/postscript',
        'exe' => 'application/octet-stream',
        'ez' => 'application/andrew-inset',
        'flv' => 'video/x-flv',
        'gtar' => 'application/x-gtar',
        'gz' => 'application/x-gzip',
        'bz2' => 'application/x-bzip',
        '7z' => 'application/x-7z-compressed',
        'hdf' => 'application/x-hdf',
        'hqx' => 'application/mac-binhex40',
        'ico' => 'image/x-icon',
        'ips' => 'application/x-ipscript',
        'ipx' => 'application/x-ipix',
        'js' => 'application/javascript',
        'jsonapi' => 'application/vnd.api+json',
        'latex' => 'application/x-latex',
        'lha' => 'application/octet-stream',
        'lsp' => 'application/x-lisp',
        'lzh' => 'application/octet-stream',
        'man' => 'application/x-troff-man',
        'me' => 'application/x-troff-me',
        'mif' => 'application/vnd.mif',
        'ms' => 'application/x-troff-ms',
        'nc' => 'application/x-netcdf',
        'oda' => 'application/oda',
        'otf' => 'font/otf',
        'pdf' => 'application/pdf',
        'pgn' => 'application/x-chess-pgn',
        'pot' => 'application/vnd.ms-powerpoint',
        'pps' => 'application/vnd.ms-powerpoint',
        'ppt' => 'application/vnd.ms-powerpoint',
        'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'ppz' => 'application/vnd.ms-powerpoint',
        'pre' => 'application/x-freelance',
        'prt' => 'application/pro_eng',
        'ps' => 'application/postscript',
        'roff' => 'application/x-troff',
        'scm' => 'application/x-lotusscreencam',
        'set' => 'application/set',
        'sh' => 'application/x-sh',
        'shar' => 'application/x-shar',
        'sit' => 'application/x-stuffit',
        'skd' => 'application/x-koan',
        'skm' => 'application/x-koan',
        'skp' => 'application/x-koan',
        'skt' => 'application/x-koan',
        'smi' => 'application/smil',
        'smil' => 'application/smil',
        'sol' => 'application/solids',
        'spl' => 'application/x-futuresplash',
        'src' => 'application/x-wais-source',
        'step' => 'application/STEP',
        'stl' => 'application/SLA',
        'stp' => 'application/STEP',
        'sv4cpio' => 'application/x-sv4cpio',
        'sv4crc' => 'application/x-sv4crc',
        'svg' => 'image/svg+xml',
        'svgz' => 'image/svg+xml',
        'swf' => 'application/x-shockwave-flash',
        't' => 'application/x-troff',
        'tar' => 'application/x-tar',
        'tcl' => 'application/x-tcl',
        'tex' => 'application/x-tex',
        'texi' => 'application/x-texinfo',
        'texinfo' => 'application/x-texinfo',
        'tr' => 'application/x-troff',
        'tsp' => 'application/dsptype',
        'ttc' => 'font/ttf',
        'ttf' => 'font/ttf',
        'unv' => 'application/i-deas',
        'ustar' => 'application/x-ustar',
        'vcd' => 'application/x-cdlink',
        'vda' => 'application/vda',
        'xlc' => 'application/vnd.ms-excel',
        'xll' => 'application/vnd.ms-excel',
        'xlm' => 'application/vnd.ms-excel',
        'xls' => 'application/vnd.ms-excel',
        'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'xlw' => 'application/vnd.ms-excel',
        'zip' => 'application/zip',
        'aif' => 'audio/x-aiff',
        'aifc' => 'audio/x-aiff',
        'aiff' => 'audio/x-aiff',
        'au' => 'audio/basic',
        'kar' => 'audio/midi',
        'mid' => 'audio/midi',
        'midi' => 'audio/midi',
        'mp2' => 'audio/mpeg',
        'mp3' => 'audio/mpeg',
        'mpga' => 'audio/mpeg',
        'ogg' => 'audio/ogg',
        'oga' => 'audio/ogg',
        'spx' => 'audio/ogg',
        'ra' => 'audio/x-realaudio',
        'ram' => 'audio/x-pn-realaudio',
        'rm' => 'audio/x-pn-realaudio',
        'rpm' => 'audio/x-pn-realaudio-plugin',
        'snd' => 'audio/basic',
        'tsi' => 'audio/TSP-audio',
        'wav' => 'audio/x-wav',
        'aac' => 'audio/aac',
        'asc' => 'text/plain',
        'c' => 'text/plain',
        'cc' => 'text/plain',
        'css' => 'text/css',
        'etx' => 'text/x-setext',
        'f' => 'text/plain',
        'f90' => 'text/plain',
        'h' => 'text/plain',
        'hh' => 'text/plain',
        'htm' => ['text/html', '*/*'],
        'ics' => 'text/calendar',
        'm' => 'text/plain',
        'rtf' => 'text/rtf',
        'rtx' => 'text/richtext',
        'sgm' => 'text/sgml',
        'sgml' => 'text/sgml',
        'tsv' => 'text/tab-separated-values',
        'tpl' => 'text/template',
        'txt' => 'text/plain',
        'text' => 'text/plain',
        'avi' => 'video/x-msvideo',
        'fli' => 'video/x-fli',
        'mov' => 'video/quicktime',
        'movie' => 'video/x-sgi-movie',
        'mpe' => 'video/mpeg',
        'mpeg' => 'video/mpeg',
        'mpg' => 'video/mpeg',
        'qt' => 'video/quicktime',
        'viv' => 'video/vnd.vivo',
        'vivo' => 'video/vnd.vivo',
        'ogv' => 'video/ogg',
        'webm' => 'video/webm',
        'mp4' => 'video/mp4',
        'm4v' => 'video/mp4',
        'f4v' => 'video/mp4',
        'f4p' => 'video/mp4',
        'm4a' => 'audio/mp4',
        'f4a' => 'audio/mp4',
        'f4b' => 'audio/mp4',
        'gif' => 'image/gif',
        'ief' => 'image/ief',
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg',
        'jpe' => 'image/jpeg',
        'pbm' => 'image/x-portable-bitmap',
        'pgm' => 'image/x-portable-graymap',
        'png' => 'image/png',
        'pnm' => 'image/x-portable-anymap',
        'ppm' => 'image/x-portable-pixmap',
        'ras' => 'image/cmu-raster',
        'rgb' => 'image/x-rgb',
        'tif' => 'image/tiff',
        'tiff' => 'image/tiff',
        'xbm' => 'image/x-xbitmap',
        'xpm' => 'image/x-xpixmap',
        'xwd' => 'image/x-xwindowdump',
        'psd' => ['application/photoshop', 'application/psd', 'image/psd', 'image/x-photoshop', 'image/photoshop', 'zz-application/zz-winassoc-psd'],
        'ice' => 'x-conference/x-cooltalk',
        'iges' => 'model/iges',
        'igs' => 'model/iges',
        'mesh' => 'model/mesh',
        'msh' => 'model/mesh',
        'silo' => 'model/mesh',
        'vrml' => 'model/vrml',
        'wrl' => 'model/vrml',
        'mime' => 'www/mime',
        'pdb' => 'chemical/x-pdb',
        'xyz' => 'chemical/x-pdb',
        'javascript' => 'application/javascript',
        'form' => 'application/x-www-form-urlencoded',
        'file' => 'multipart/form-data',
        'xhtml-mobile' => 'application/vnd.wap.xhtml+xml',
        'atom' => 'application/atom+xml',
        'amf' => 'application/x-amf',
        'wap' => ['text/vnd.wap.wml', 'text/vnd.wap.wmlscript', 'image/vnd.wap.wbmp'],
        'wml' => 'text/vnd.wap.wml',
        'wmlscript' => 'text/vnd.wap.wmlscript',
        'wbmp' => 'image/vnd.wap.wbmp',
        'woff' => 'application/x-font-woff',
        'appcache' => 'text/cache-manifest',
        'manifest' => 'text/cache-manifest',
        'htc' => 'text/x-component',
        'rdf' => 'application/xml',
        'crx' => 'application/x-chrome-extension',
        'oex' => 'application/x-opera-extension',
        'xpi' => 'application/x-xpinstall',
        'safariextz' => 'application/octet-stream',
        'webapp' => 'application/x-web-app-manifest+json',
        'vcf' => 'text/x-vcard',
        'vtt' => 'text/vtt',
        'mkv' => 'video/x-matroska',
        'pkpass' => 'application/vnd.apple.pkpass',
        'ajax' => 'text/html',
        'bmp' => 'image/bmp'
    ];

    /**
     * Protocol header to send to the client
     *
     * @var string
     */
    protected $_protocol = 'HTTP/1.1';

    /**
     * Status code to send to the client
     *
     * @var int
     */
    protected $_status = 200;

    /**
     * Content type to send. This can be an 'extension' that will be transformed using the $_mimetypes array
     * or a complete mime-type
     *
     * @var string
     */
    protected $_contentType = 'text/html';

    /**
     * File object for file to be read out as response
     *
     * @var \Cake\Filesystem\File|null
     */
    protected $_file;

    /**
     * File range. Used for requesting ranges of files.
     *
     * @var array
     */
    protected $_fileRange = [];

    /**
     * The charset the response body is encoded with
     *
     * @var string
     */
    protected $_charset = 'UTF-8';

    /**
     * Holds all the cache directives that will be converted
     * into headers when sending the request
     *
     * @var array
     */
    protected $_cacheDirectives = [];

    /**
     * Collection of cookies to send to the client
     *
     * @var \Cake\Http\Cookie\CookieCollection
     */
    protected $_cookies = null;

    /**
     * Reason Phrase
     *
     * @var string
     */
    protected $_reasonPhrase = 'OK';

    /**
     * Stream mode options.
     *
     * @var string
     */
    protected $_streamMode = 'wb+';

    /**
     * Stream target or resource object.
     *
     * @var string|resource
     */
    protected $_streamTarget = 'php://memory';

    /**
     * Constructor
     *
     * @param array $options list of parameters to setup the response. Possible values are:
     *  - body: the response text that should be sent to the client
     *  - status: the HTTP status code to respond with
     *  - type: a complete mime-type string or an extension mapped in this class
     *  - charset: the charset for the response body
     */
    public function __construct(array $options = [])
    {
        if (isset($options['streamTarget'])) {
            $this->_streamTarget = $options['streamTarget'];
        }
        if (isset($options['streamMode'])) {
            $this->_streamMode = $options['streamMode'];
        }
        if (isset($options['stream'])) {
            if (!$options['stream'] instanceof StreamInterface) {
                throw new InvalidArgumentException('Stream option must be an object that implements StreamInterface');
            }
            $this->stream = $options['stream'];
        } else {
            $this->_createStream();
        }
        if (isset($options['body'])) {
            $this->stream->write($options['body']);
        }
        if (isset($options['status'])) {
            $this->_setStatus($options['status']);
        }
        if (!isset($options['charset'])) {
            $options['charset'] = Configure::read('App.encoding');
        }
        $this->_charset = $options['charset'];
        if (isset($options['type'])) {
            $this->_contentType = $this->resolveType($options['type']);
        }
        $this->_setContentType();
        $this->_cookies = new CookieCollection();
    }

    /**
     * Creates the stream object.
     *
     * @return void
     */
    protected function _createStream()
    {
        $this->stream = new Stream($this->_streamTarget, $this->_streamMode);
    }

    /**
     * Formats the Content-Type header based on the configured contentType and charset
     * the charset will only be set in the header if the response is of type text/*
     *
     * @return void
     */
    protected function _setContentType()
    {
        if (in_array($this->_status, [304, 204])) {
            $this->_clearHeader('Content-Type');

            return;
        }
        $whitelist = [
            'application/javascript', 'application/json', 'application/xml', 'application/rss+xml'
        ];

        $charset = false;
        if ($this->_charset &&
            (strpos($this->_contentType, 'text/') === 0 || in_array($this->_contentType, $whitelist))
        ) {
            $charset = true;
        }

        if ($charset) {
            $this->_setHeader('Content-Type', "{$this->_contentType}; charset={$this->_charset}");
        } else {
            $this->_setHeader('Content-Type', (string)$this->_contentType);
        }
    }

    /**
     * Return an instance with an updated location header.
     *
     * If the current status code is 200, it will be replaced
     * with 302.
     *
     * @param string $url The location to redirect to.
     * @return static A new response with the Location header set.
     */
    public function withLocation($url)
    {
        $new = $this->withHeader('Location', $url);
        if ($new->_status === 200) {
            $new->_status = 302;
        }

        return $new;
    }

    /**
     * Sets a header.
     *
     * @param string $header Header key.
     * @param string $value Header value.
     * @return void
     */
    protected function _setHeader($header, $value)
    {
        $normalized = strtolower($header);
        $this->headerNames[$normalized] = $header;
        $this->headers[$header] = [$value];
    }

    /**
     * Clear header
     *
     * @param string $header Header key.
     * @return void
     */
    protected function _clearHeader($header)
    {
        $normalized = strtolower($header);
        if (!isset($this->headerNames[$normalized])) {
            return;
        }
        $original = $this->headerNames[$normalized];
        unset($this->headerNames[$normalized], $this->headers[$original]);
    }

    /**
     * Gets the response status code.
     *
     * The status code is a 3-digit integer result code of the server's attempt
     * to understand and satisfy the request.
     *
     * @return int Status code.
     */
    public function getStatusCode()
    {
        return $this->_status;
    }

    /**
     * Return an instance with the specified status code and, optionally, reason phrase.
     *
     * If no reason phrase is specified, implementations MAY choose to default
     * to the RFC 7231 or IANA recommended reason phrase for the response's
     * status code.
     *
     * This method MUST be implemented in such a way as to retain the
     * immutability of the message, and MUST return an instance that has the
     * updated status and reason phrase.
     *
     * If the status code is 304 or 204, the existing Content-Type header
     * will be cleared, as these response codes have no body.
     *
     * @link https://tools.ietf.org/html/rfc7231#section-6
     * @link https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
     * @param int $code The 3-digit integer result code to set.
     * @param string $reasonPhrase The reason phrase to use with the
     *     provided status code; if none is provided, implementations MAY
     *     use the defaults as suggested in the HTTP specification.
     * @return static
     * @throws \InvalidArgumentException For invalid status code arguments.
     */
    public function withStatus($code, $reasonPhrase = '')
    {
        $new = clone $this;
        $new->_setStatus($code, $reasonPhrase);

        return $new;
    }

    /**
     * Modifier for response status
     *
     * @param int $code The code to set.
     * @param string $reasonPhrase The response reason phrase.
     * @return void
     * @throws \InvalidArgumentException For invalid status code arguments.
     */
    protected function _setStatus($code, $reasonPhrase = '')
    {
        if (!isset($this->_statusCodes[$code])) {
            throw new InvalidArgumentException(sprintf(
                'Invalid status code: %s. Use a valid HTTP status code in range 1xx - 5xx.',
                $code
            ));
        }

        $this->_status = $code;
        if (empty($reasonPhrase)) {
            $reasonPhrase = $this->_statusCodes[$code];
        }
        $this->_reasonPhrase = $reasonPhrase;
        $this->_setContentType();
    }

    /**
     * Gets the response reason phrase associated with the status code.
     *
     * Because a reason phrase is not a required element in a response
     * status line, the reason phrase value MAY be null. Implementations MAY
     * choose to return the default RFC 7231 recommended reason phrase (or those
     * listed in the IANA HTTP Status Code Registry) for the response's
     * status code.
     *
     * @link https://tools.ietf.org/html/rfc7231#section-6
     * @link http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
     * @return string Reason phrase; must return an empty string if none present.
     */
    public function getReasonPhrase()
    {
        return $this->_reasonPhrase;
    }

    /**
     * Returns the current content type.
     *
     * @return string
     */
    public function getType()
    {
        return $this->_contentType;
    }

    /**
     * Get an updated response with the content type set.
     *
     * If you attempt to set the type on a 304 or 204 status code response, the
     * content type will not take effect as these status codes do not have content-types.
     *
     * @param string $contentType Either a file extension which will be mapped to a mime-type or a concrete mime-type.
     * @return static
     */
    public function withType($contentType)
    {
        $mappedType = $this->resolveType($contentType);
        $new = clone $this;
        $new->_contentType = $mappedType;
        $new->_setContentType();

        return $new;
    }

    /**
     * Translate and validate content-types.
     *
     * @param string $contentType The content-type or type alias.
     * @return string The resolved content-type
     * @throws \InvalidArgumentException When an invalid content-type or alias is used.
     */
    protected function resolveType($contentType)
    {
        $mapped = $this->getMimeType($contentType);
        if ($mapped) {
            return is_array($mapped) ? current($mapped) : $mapped;
        }
        if (strpos($contentType, '/') === false) {
            throw new InvalidArgumentException(sprintf('"%s" is an invalid content type.', $contentType));
        }

        return $contentType;
    }

    /**
     * Returns the mime type definition for an alias
     *
     * e.g `getMimeType('pdf'); // returns 'application/pdf'`
     *
     * @param string $alias the content type alias to map
     * @return mixed String mapped mime type or false if $alias is not mapped
     */
    public function getMimeType($alias)
    {
        if (isset($this->_mimeTypes[$alias])) {
            return $this->_mimeTypes[$alias];
        }

        return false;
    }

    /**
     * Maps a content-type back to an alias
     *
     * e.g `mapType('application/pdf'); // returns 'pdf'`
     *
     * @param string|array $ctype Either a string content type to map, or an array of types.
     * @return string|array|null Aliases for the types provided.
     */
    public function mapType($ctype)
    {
        if (is_array($ctype)) {
            return array_map([$this, 'mapType'], $ctype);
        }

        foreach ($this->_mimeTypes as $alias => $types) {
            if (in_array($ctype, (array)$types)) {
                return $alias;
            }
        }

        return null;
    }

    /**
     * Returns the current charset.
     *
     * @return string
     */
    public function getCharset()
    {
        return $this->_charset;
    }

    /**
     * Get a new instance with an updated charset.
     *
     * @param string $charset Character set string.
     * @return static
     */
    public function withCharset($charset)
    {
        $new = clone $this;
        $new->_charset = $charset;
        $new->_setContentType();

        return $new;
    }

    /**
     * Create a new instance with headers to instruct the client to not cache the response
     *
     * @return static
     */
    public function withDisabledCache()
    {
        return $this->withHeader('Expires', 'Mon, 26 Jul 1997 05:00:00 GMT')
            ->withHeader('Last-Modified', gmdate('D, d M Y H:i:s') . ' GMT')
            ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0');
    }

    /**
     * Create a new instance with the headers to enable client caching.
     *
     * @param string $since a valid time since the response text has not been modified
     * @param string $time a valid time for cache expiry
     * @return static
     */
    public function withCache($since, $time = '+1 day')
    {
        if (!is_int($time)) {
            $time = strtotime($time);
        }

        return $this->withHeader('Date', gmdate('D, j M Y G:i:s ', time()) . 'GMT')
            ->withModified($since)
            ->withExpires($time)
            ->withSharable(true)
            ->withMaxAge($time - time());
    }

    /**
     * Create a new instace with the public/private Cache-Control directive set.
     *
     * @param bool $public If set to true, the Cache-Control header will be set as public
     *   if set to false, the response will be set to private.
     * @param int|null $time time in seconds after which the response should no longer be considered fresh.
     * @return static
     */
    public function withSharable($public, $time = null)
    {
        $new = clone $this;
        unset($new->_cacheDirectives['private'], $new->_cacheDirectives['public']);

        $key = $public ? 'public' : 'private';
        $new->_cacheDirectives[$key] = true;

        if ($time !== null) {
            $new->_cacheDirectives['max-age'] = $time;
        }
        $new->_setCacheControl();

        return $new;
    }

    /**
     * Create a new instance with the Cache-Control s-maxage directive.
     *
     * The max-age is the number of seconds after which the response should no longer be considered
     * a good candidate to be fetched from a shared cache (like in a proxy server).
     *
     * @param int $seconds The number of seconds for shared max-age
     * @return static
     */
    public function withSharedMaxAge($seconds)
    {
        $new = clone $this;
        $new->_cacheDirectives['s-maxage'] = $seconds;
        $new->_setCacheControl();

        return $new;
    }

    /**
     * Create an instance with Cache-Control max-age directive set.
     *
     * The max-age is the number of seconds after which the response should no longer be considered
     * a good candidate to be fetched from the local (client) cache.
     *
     * @param int $seconds The seconds a cached response can be considered valid
     * @return static
     */
    public function withMaxAge($seconds)
    {
        $new = clone $this;
        $new->_cacheDirectives['max-age'] = $seconds;
        $new->_setCacheControl();

        return $new;
    }

    /**
     * Create an instance with Cache-Control must-revalidate directive set.
     *
     * Sets the Cache-Control must-revalidate directive.
     * must-revalidate indicates that the response should not be served
     * stale by a cache under any circumstance without first revalidating
     * with the origin.
     *
     * @param bool $enable If boolean sets or unsets the directive.
     * @return static
     */
    public function withMustRevalidate($enable)
    {
        $new = clone $this;
        if ($enable) {
            $new->_cacheDirectives['must-revalidate'] = true;
        } else {
            unset($new->_cacheDirectives['must-revalidate']);
        }
        $new->_setCacheControl();

        return $new;
    }

    /**
     * Helper method to generate a valid Cache-Control header from the options set
     * in other methods
     *
     * @return void
     */
    protected function _setCacheControl()
    {
        $control = '';
        foreach ($this->_cacheDirectives as $key => $val) {
            $control .= $val === true ? $key : sprintf('%s=%s', $key, $val);
            $control .= ', ';
        }
        $control = rtrim($control, ', ');
        $this->_setHeader('Cache-Control', $control);
    }

    /**
     * Create a new instance with the Expires header set.
     *
     * ### Examples:
     *
     * ```
     * // Will Expire the response cache now
     * $response->withExpires('now')
     *
     * // Will set the expiration in next 24 hours
     * $response->withExpires(new DateTime('+1 day'))
     * ```
     *
     * @param string|\DateTime $time Valid time string or \DateTime instance.
     * @return static
     */
    public function withExpires($time)
    {
        $date = $this->_getUTCDate($time);

        return $this->withHeader('Expires', $date->format('D, j M Y H:i:s') . ' GMT');
    }

    /**
     * Create a new instance with the Last-Modified header set.
     *
     * ### Examples:
     *
     * ```
     * // Will Expire the response cache now
     * $response->withModified('now')
     *
     * // Will set the expiration in next 24 hours
     * $response->withModified(new DateTime('+1 day'))
     * ```
     *
     * @param string|\DateTime $time Valid time string or \DateTime instance.
     * @return static
     */
    public function withModified($time)
    {
        $date = $this->_getUTCDate($time);

        return $this->withHeader('Last-Modified', $date->format('D, j M Y H:i:s') . ' GMT');
    }

    /**
     * Sets the response as Not Modified by removing any body contents
     * setting the status code to "304 Not Modified" and removing all
     * conflicting headers
     *
     * *Warning* This method mutates the response in-place and should be avoided.
     *
     * @return void
     */
    public function notModified()
    {
        $this->_createStream();
        $this->_setStatus(304);

        $remove = [
            'Allow',
            'Content-Encoding',
            'Content-Language',
            'Content-Length',
            'Content-MD5',
            'Content-Type',
            'Last-Modified'
        ];
        foreach ($remove as $header) {
            $this->_clearHeader($header);
        }
    }

    /**
     * Create a new instance as 'not modified'
     *
     * This will remove any body contents set the status code
     * to "304" and removing headers that describe
     * a response body.
     *
     * @return static
     */
    public function withNotModified()
    {
        $new = $this->withStatus(304);
        $new->_createStream();
        $remove = [
            'Allow',
            'Content-Encoding',
            'Content-Language',
            'Content-Length',
            'Content-MD5',
            'Content-Type',
            'Last-Modified'
        ];
        foreach ($remove as $header) {
            $new = $new->withoutHeader($header);
        }

        return $new;
    }

    /**
     * Create a new instance with the Vary header set.
     *
     * If an array is passed values will be imploded into a comma
     * separated string. If no parameters are passed, then an
     * array with the current Vary header value is returned
     *
     * @param string|array $cacheVariances A single Vary string or an array
     *   containing the list for variances.
     * @return static
     */
    public function withVary($cacheVariances)
    {
        return $this->withHeader('Vary', (array)$cacheVariances);
    }

    /**
     * Create a new instance with the Etag header set.
     *
     * Etags are a strong indicative that a response can be cached by a
     * HTTP client. A bad way of generating Etags is creating a hash of
     * the response output, instead generate a unique hash of the
     * unique components that identifies a request, such as a
     * modification time, a resource Id, and anything else you consider it
     * that makes the response unique.
     *
     * The second parameter is used to inform clients that the content has
     * changed, but semantically it is equivalent to existing cached values. Consider
     * a page with a hit counter, two different page views are equivalent, but
     * they differ by a few bytes. This permits the Client to decide whether they should
     * use the cached data.
     *
     * @param string $hash The unique hash that identifies this response
     * @param bool $weak Whether the response is semantically the same as
     *   other with the same hash or not. Defaults to false
     * @return static
     */
    public function withEtag($hash, $weak = false)
    {
        $hash = sprintf('%s"%s"', $weak ? 'W/' : null, $hash);

        return $this->withHeader('Etag', $hash);
    }

    /**
     * Returns a DateTime object initialized at the $time param and using UTC
     * as timezone
     *
     * @param string|int|\DateTime|null $time Valid time string or \DateTime instance.
     * @return \DateTime
     */
    protected function _getUTCDate($time = null)
    {
        if ($time instanceof DateTime) {
            $result = clone $time;
        } elseif (is_int($time)) {
            $result = new DateTime(date('Y-m-d H:i:s', $time));
        } else {
            $result = new DateTime($time);
        }
        $result->setTimezone(new DateTimeZone('UTC'));

        return $result;
    }

    /**
     * Sets the correct output buffering handler to send a compressed response. Responses will
     * be compressed with zlib, if the extension is available.
     *
     * @return bool false if client does not accept compressed responses or no handler is available, true otherwise
     */
    public function compress()
    {
        $compressionEnabled = ini_get('zlib.output_compression') !== '1' &&
            extension_loaded('zlib') &&
            (strpos(env('HTTP_ACCEPT_ENCODING'), 'gzip') !== false);

        return $compressionEnabled && ob_start('ob_gzhandler');
    }

    /**
     * Returns whether the resulting output will be compressed by PHP
     *
     * @return bool
     */
    public function outputCompressed()
    {
        return strpos(env('HTTP_ACCEPT_ENCODING'), 'gzip') !== false
            && (ini_get('zlib.output_compression') === '1' || in_array('ob_gzhandler', ob_list_handlers()));
    }

    /**
     * Create a new instance with the Content-Disposition header set.
     *
     * @param string $filename The name of the file as the browser will download the response
     * @return static
     */
    public function withDownload($filename)
    {
        return $this->withHeader('Content-Disposition', 'attachment; filename="' . $filename . '"');
    }

    /**
     * Create a new response with the Content-Length header set.
     *
     * @param int|string $bytes Number of bytes
     * @return static
     */
    public function withLength($bytes)
    {
        return $this->withHeader('Content-Length', (string)$bytes);
    }

    /**
     * Create a new response with the Link header set.
     *
     * ### Examples
     *
     * ```
     * $response = $response->withAddedLink('http://example.com?page=1', ['rel' => 'prev'])
     *     ->withAddedLink('http://example.com?page=3', ['rel' => 'next']);
     * ```
     *
     * Will generate:
     *
     * ```
     * Link: <http://example.com?page=1>; rel="prev"
     * Link: <http://example.com?page=3>; rel="next"
     * ```
     *
     * @param string $url The LinkHeader url.
     * @param array $options The LinkHeader params.
     * @return static
     * @since 3.6.0
     */
    public function withAddedLink($url, array $options = [])
    {
        $params = [];
        foreach ($options as $key => $option) {
            $params[] = $key . '="' . $option . '"';
        }

        $param = '';
        if ($params) {
            $param = '; ' . implode('; ', $params);
        }

        return $this->withAddedHeader('Link', '<' . $url . '>' . $param);
    }

    /**
     * Checks whether a response has not been modified according to the 'If-None-Match'
     * (Etags) and 'If-Modified-Since' (last modification date) request
     * headers. If the response is detected to be not modified, it
     * is marked as so accordingly so the client can be informed of that.
     *
     * In order to mark a response as not modified, you need to set at least
     * the Last-Modified etag response header before calling this method. Otherwise
     * a comparison will not be possible.
     *
     * *Warning* This method mutates the response in-place and should be avoided.
     *
     * @param \Cake\Http\ServerRequest $request Request object
     * @return bool Whether the response was marked as not modified or not.
     */
    public function checkNotModified(ServerRequest $request)
    {
        $etags = preg_split('/\s*,\s*/', (string)$request->getHeaderLine('If-None-Match'), 0, PREG_SPLIT_NO_EMPTY);
        $responseTag = $this->getHeaderLine('Etag');
        if ($responseTag) {
            $etagMatches = in_array('*', $etags) || in_array($responseTag, $etags);
        }

        $modifiedSince = $request->getHeaderLine('If-Modified-Since');
        if ($modifiedSince && $this->hasHeader('Last-Modified')) {
            $timeMatches = strtotime($this->getHeaderLine('Last-Modified')) === strtotime($modifiedSince);
        }
        $checks = compact('etagMatches', 'timeMatches');
        if (empty($checks)) {
            return false;
        }
        $notModified = !in_array(false, $checks, true);
        if ($notModified) {
            $this->notModified();
        }

        return $notModified;
    }

    /**
     * String conversion. Fetches the response body as a string.
     * Does *not* send headers.
     * If body is a callable, a blank string is returned.
     *
     * @return string
     */
    public function __toString()
    {
        $this->stream->rewind();

        return (string)$this->stream->getContents();
    }

    /**
     * Create a new response with a cookie set.
     *
     * ### Options
     *
     * - `value`: Value of the cookie
     * - `expire`: Time the cookie expires in
     * - `path`: Path the cookie applies to
     * - `domain`: Domain the cookie is for.
     * - `secure`: Is the cookie https?
     * - `httpOnly`: Is the cookie available in the client?
     *
     * ### Examples
     *
     * ```
     * // set scalar value with defaults
     * $response = $response->withCookie('remember_me', 1);
     *
     * // customize cookie attributes
     * $response = $response->withCookie('remember_me', ['path' => '/login']);
     *
     * // add a cookie object
     * $response = $response->withCookie(new Cookie('remember_me', 1));
     * ```
     *
     * @param string|\Cake\Http\Cookie\Cookie $name The name of the cookie to set, or a cookie object
     * @param array|string $data Either a string value, or an array of cookie options.
     * @return static
     */
    public function withCookie($name, $data = '')
    {
        if ($name instanceof Cookie) {
            $cookie = $name;
        } else {
            if (!is_array($data)) {
                $data = ['value' => $data];
            }
            $data += [
                'value' => '',
                'expire' => 0,
                'path' => '/',
                'domain' => '',
                'secure' => false,
                'httpOnly' => false
            ];
            $expires = $data['expire'] ? new DateTime('@' . $data['expire']) : null;
            $cookie = new Cookie(
                $name,
                $data['value'],
                $expires,
                $data['path'],
                $data['domain'],
                $data['secure'],
                $data['httpOnly']
            );
        }

        $new = clone $this;
        $new->_cookies = $new->_cookies->add($cookie);

        return $new;
    }

    /**
     * Create a new response with an expired cookie set.
     *
     * ### Options
     *
     * - `path`: Path the cookie applies to
     * - `domain`: Domain the cookie is for.
     * - `secure`: Is the cookie https?
     * - `httpOnly`: Is the cookie available in the client?
     *
     * ### Examples
     *
     * ```
     * // set scalar value with defaults
     * $response = $response->withExpiredCookie('remember_me');
     *
     * // customize cookie attributes
     * $response = $response->withExpiredCookie('remember_me', ['path' => '/login']);
     *
     * // add a cookie object
     * $response = $response->withExpiredCookie(new Cookie('remember_me'));
     * ```
     *
     * @param string|\Cake\Http\Cookie\CookieInterface $name The name of the cookie to expire, or a cookie object
     * @param array $options An array of cookie options.
     * @return static
     */
    public function withExpiredCookie($name, array $options = [])
    {
        if ($name instanceof CookieInterface) {
            $cookie = $name->withExpired();
        } else {
            $options += [
                'path' => '/',
                'domain' => '',
                'secure' => false,
                'httpOnly' => false
            ];

            $cookie = new Cookie(
                $name,
                '',
                DateTime::createFromFormat('U', 1),
                $options['path'],
                $options['domain'],
                $options['secure'],
                $options['httpOnly']
            );
        }

        $new = clone $this;
        $new->_cookies = $new->_cookies->add($cookie);

        return $new;
    }

    /**
     * Read a single cookie from the response.
     *
     * This method provides read access to pending cookies. It will
     * not read the `Set-Cookie` header if set.
     *
     * @param string $name The cookie name you want to read.
     * @return array|null Either the cookie data or null
     */
    public function getCookie($name)
    {
        if (!$this->_cookies->has($name)) {
            return null;
        }

        $cookie = $this->_cookies->get($name);

        return $this->convertCookieToArray($cookie);
    }

    /**
     * Get all cookies in the response.
     *
     * Returns an associative array of cookie name => cookie data.
     *
     * @return array
     */
    public function getCookies()
    {
        $out = [];
        foreach ($this->_cookies as $cookie) {
            $out[$cookie->getName()] = $this->convertCookieToArray($cookie);
        }

        return $out;
    }

    /**
     * Convert the cookie into an array of its properties.
     *
     * This method is compatible with the historical behavior of Cake\Http\Response,
     * where `httponly` is `httpOnly` and `expires` is `expire`
     *
     * @param \Cake\Http\Cookie\CookieInterface $cookie Cookie object.
     * @return array
     */
    protected function convertCookieToArray(CookieInterface $cookie)
    {
        return [
            'name' => $cookie->getName(),
            'value' => $cookie->getStringValue(),
            'path' => $cookie->getPath(),
            'domain' => $cookie->getDomain(),
            'secure' => $cookie->isSecure(),
            'httpOnly' => $cookie->isHttpOnly(),
            'expire' => $cookie->getExpiresTimestamp()
        ];
    }

    /**
     * Get the CookieCollection from the response
     *
     * @return \Cake\Http\Cookie\CookieCollection
     */
    public function getCookieCollection()
    {
        return $this->_cookies;
    }

    /**
     * Get a CorsBuilder instance for defining CORS headers.
     *
     * @param \Cake\Http\ServerRequest $request Request object
     * @return \Cake\Http\CorsBuilder A builder object the provides a fluent interface for defining
     *   additional CORS headers.
     */
    public function cors(ServerRequest $request)
    {
        $origin = $request->getHeaderLine('Origin');
        $ssl = $request->is('ssl');

        return new CorsBuilder($this, $origin, $ssl);
    }

    /**
     * Create a new instance that is based on a file.
     *
     * This method will augment both the body and a number of related headers.
     *
     * If `$_SERVER['HTTP_RANGE']` is set, a slice of the file will be
     * returned instead of the entire file.
     *
     * ### Options keys
     *
     * - name: Alternate download name
     * - download: If `true` sets download header and forces file to
     *   be downloaded rather than displayed inline.
     *
     * @param string $path Absolute path to file.
     * @param array $options Options See above.
     * @return static
     * @throws \Cake\Http\Exception\NotFoundException
     */
    public function withFile($path, array $options = [])
    {
        $file = $this->validateFile($path);
        $options += [
            'name' => null,
            'download' => null
        ];

        $extension = strtolower($file->ext());
        $mapped = $this->getMimeType($extension);
        if ((!$extension || !$mapped) && $options['download'] === null) {
            $options['download'] = true;
        }

        $new = clone $this;
        if ($mapped) {
            $new = $new->withType($extension);
        }

        $fileSize = $file->size();
        if ($options['download']) {
            $agent = env('HTTP_USER_AGENT');

            if (preg_match('%Opera(/| )([0-9].[0-9]{1,2})%', $agent)) {
                $contentType = 'application/octet-stream';
            } elseif (preg_match('/MSIE ([0-9].[0-9]{1,2})/', $agent)) {
                $contentType = 'application/force-download';
            }

            if (isset($contentType)) {
                $new = $new->withType($contentType);
            }
            $name = $options['name'] ?: $file->name;
            $new = $new->withDownload($name)
                ->withHeader('Content-Transfer-Encoding', 'binary');
        }

        $new = $new->withHeader('Accept-Ranges', 'bytes');
        $httpRange = env('HTTP_RANGE');
        if (isset($httpRange)) {
            $new->_fileRange($file, $httpRange);
        } else {
            $new = $new->withHeader('Content-Length', (string)$fileSize);
        }
        $new->_file = $file;
        $new->stream = new Stream($file->path, 'rb');

        return $new;
    }

    /**
     * Convenience method to set a string into the response body
     *
     * @param string $string The string to be sent
     * @return static
     */
    public function withStringBody($string)
    {
        $new = clone $this;
        $new->_createStream();
        $new->stream->write((string)$string);

        return $new;
    }

    /**
     * Validate a file path is a valid response body.
     *
     * @param string $path The path to the file.
     * @throws \Cake\Http\Exception\NotFoundException
     * @return \Cake\Filesystem\File
     */
    protected function validateFile($path)
    {
        if (strpos($path, '../') !== false || strpos($path, '..\\') !== false) {
            throw new NotFoundException(__d('cake', 'The requested file contains `..` and will not be read.'));
        }

        $file = new File($path);
        if (!$file->exists() || !$file->readable()) {
            if (Configure::read('debug')) {
                throw new NotFoundException(sprintf('The requested file %s was not found or not readable', $path));
            }
            throw new NotFoundException(__d('cake', 'The requested file was not found'));
        }

        return $file;
    }

    /**
     * Get the current file if one exists.
     *
     * @return \Cake\Filesystem\File|null The file to use in the response or null
     */
    public function getFile()
    {
        return $this->_file;
    }

    /**
     * Apply a file range to a file and set the end offset.
     *
     * If an invalid range is requested a 416 Status code will be used
     * in the response.
     *
     * @param \Cake\Filesystem\File $file The file to set a range on.
     * @param string $httpRange The range to use.
     * @return void
     */
    protected function _fileRange($file, $httpRange)
    {
        $fileSize = $file->size();
        $lastByte = $fileSize - 1;
        $start = 0;
        $end = $lastByte;

        preg_match('/^bytes\s*=\s*(\d+)?\s*-\s*(\d+)?$/', $httpRange, $matches);
        if ($matches) {
            $start = $matches[1];
            $end = isset($matches[2]) ? $matches[2] : '';
        }

        if ($start === '') {
            $start = $fileSize - $end;
            $end = $lastByte;
        }
        if ($end === '') {
            $end = $lastByte;
        }

        if ($start > $end || $end > $lastByte || $start > $lastByte) {
            $this->_setStatus(416);
            $this->_setHeader('Content-Range', 'bytes 0-' . $lastByte . '/' . $fileSize);

            return;
        }

        $this->_setHeader('Content-Length', $end - $start + 1);
        $this->_setHeader('Content-Range', 'bytes ' . $start . '-' . $end . '/' . $fileSize);
        $this->_setStatus(206);
        $this->_fileRange = [$start, $end];
    }

    /**
     * Returns an array that can be used to describe the internal state of this
     * object.
     *
     * @return array
     */
    public function __debugInfo()
    {
        return [
            'status' => $this->_status,
            'contentType' => $this->_contentType,
            'headers' => $this->headers,
            'file' => $this->_file,
            'fileRange' => $this->_fileRange,
            'cookies' => $this->_cookies,
            'cacheDirectives' => $this->_cacheDirectives,
            'body' => (string)$this->getBody(),
        ];
    }
}
