<?php
session_start();

// Handle GET form submissions where the browser stripped ?url=
if (empty($_GET['url']) && !empty($_GET['__proxy_action'])) {
    $baseAction = $_GET['__proxy_action'];
    $params = $_GET;
    unset($params['__proxy_action']);

    $separator = (strpos($baseAction, '?') === false) ? '?' : '&';
    $rebuiltUrl = $baseAction . (!empty($params) ? $separator . http_build_query($params) : '');

    header('Location: proxy.php?url=' . urlencode($rebuiltUrl));
    exit;
}

if (!isset($_GET['url']) || empty(trim($_GET['url']))) {
    http_response_code(400);
    exit("Missing 'url' query parameter.");
}

// Percent-encode spaces, brackets, pipes, and non-ASCII characters rejected by libcurl
function sanitizeUrlForCurl(string $url): string {
    $parts = parse_url($url);
    if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
        return $url;
    }

    $clean = $parts['scheme'] . '://';
    if (!empty($parts['user'])) {
        $clean .= $parts['user'] . (!empty($parts['pass']) ? ':' . $parts['pass'] : '') . '@';
    }
    $clean .= $parts['host'];
    if (!empty($parts['port'])) {
        $clean .= ':' . $parts['port'];
    }

    $encodePart = function (string $str): string {
        $str = preg_replace('/%(?![0-9A-Fa-f]{2})/', '%25', $str);
        return preg_replace_callback('/[^A-Za-z0-9\-._~:@!$&\'()*+,;=\/?%]/', function ($m) {
            return rawurlencode($m[0]);
        }, $str);
    };

    if (!empty($parts['path'])) {
        $clean .= $encodePart($parts['path']);
    }
    if (isset($parts['query']) && $parts['query'] !== '') {
        $clean .= '?' . $encodePart($parts['query']);
    }
    if (isset($parts['fragment']) && $parts['fragment'] !== '') {
        $clean .= '#' . $encodePart($parts['fragment']);
    }

    return $clean;
}

$targetUrl = sanitizeUrlForCurl(trim($_GET['url']));
$parsed = parse_url($targetUrl);

if (!$parsed || !isset($parsed['scheme']) || !in_array(strtolower($parsed['scheme']), ['http', 'https'], true) || empty($parsed['host'])) {
    http_response_code(400);
    exit("Invalid URL. Only HTTP and HTTPS are supported.");
}

// Block private and reserved IP addresses (SSRF protection)
$ip = gethostbyname($parsed['host']);
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    http_response_code(403);
    exit("Access to local or private network addresses is blocked.");
}

// Per-user server-side cookie jar so login sessions persist across requests
$cookieFile = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'proxy_cookies_' . preg_replace('/[^a-zA-Z0-9]/', '', session_id()) . '.txt';

// Spoof Origin and Referer to match the target domain (required by login/CSRF checks)
$originBase = $parsed['scheme'] . '://' . $parsed['host'] . (!empty($parsed['port']) ? ':' . $parsed['port'] : '');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$forwardHeaders = [
    'Accept: ' . ($_SERVER['HTTP_ACCEPT'] ?? '*/*'),
    'Accept-Language: ' . ($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? 'en-US,en;q=0.9'),
    'Origin: ' . $originBase,
    'Referer: ' . $targetUrl,
];

if (!empty($_SERVER['CONTENT_TYPE'])) {
    $forwardHeaders[] = 'Content-Type: ' . $_SERVER['CONTENT_TYPE'];
}
if (!empty($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    $forwardHeaders[] = 'X-Requested-With: ' . $_SERVER['HTTP_X_REQUESTED_WITH'];
}
if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
    $forwardHeaders[] = 'Authorization: ' . $_SERVER['HTTP_AUTHORIZATION'];
}

$contentDisposition = '';

$curlOptions = [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_MAXREDIRS      => 8,
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_CUSTOMREQUEST  => $method,
    CURLOPT_COOKIEJAR      => $cookieFile,
    CURLOPT_COOKIEFILE     => $cookieFile,
    CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    CURLOPT_HTTPHEADER     => $forwardHeaders,
    CURLOPT_HEADERFUNCTION => function ($ch, $headerLine) use (&$contentDisposition) {
        if (stripos($headerLine, 'Content-Disposition:') === 0) {
            $contentDisposition = trim($headerLine);
        }
        return strlen($headerLine);
    },
];

if ($method !== 'GET' && $method !== 'HEAD') {
    $rawBody = file_get_contents('php://input');
    $curlOptions[CURLOPT_POSTFIELDS] = !empty($_POST) && empty($rawBody) ? http_build_query($_POST) : $rawBody;
}

$ch = curl_init($targetUrl);
curl_setopt_array($ch, $curlOptions);

$body = curl_exec($ch);
if ($body === false) {
    $error = curl_error($ch);
    curl_close($ch);
    http_response_code(502);
    exit("Failed to fetch target URL: " . htmlspecialchars($error));
}

$statusCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: 'application/octet-stream';
$finalUrl    = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $targetUrl;
curl_close($ch);

http_response_code($statusCode);
header("Content-Type: " . $contentType);
if ($contentDisposition !== '') {
    header($contentDisposition);
}

// Helper: Resolve relative URLs to absolute URLs
function resolveUrl(string $rel, string $base): string {
    if ($rel === '' || preg_match('/^(data:|blob:|javascript:|mailto:|#)/i', $rel)) {
        return $rel;
    }
    if (parse_url($rel, PHP_URL_SCHEME) !== null) {
        return $rel;
    }
    $baseParts = parse_url($base);
    $scheme = $baseParts['scheme'] ?? 'https';
    $host   = $baseParts['host'] ?? '';
    $port   = isset($baseParts['port']) ? ':' . $baseParts['port'] : '';

    if (strpos($rel, '//') === 0) {
        return $scheme . ':' . $rel;
    }
    if ($rel[0] === '/') {
        return $scheme . '://' . $host . $port . $rel;
    }

    $path = $baseParts['path'] ?? '/';
    $dir  = preg_replace('#/[^/]*$#', '/', $path);
    $abs  = $host . $port . $dir . $rel;

    $re = ['#(/\.?/)#', '#/(?!\.\.)[^/]+/\.\./#'];
    for ($n = 1; $n > 0; $abs = preg_replace($re, '/', $abs, -1, $n)) {}

    return $scheme . '://' . $abs;
}

function toProxyUrl(string $rawUrl, string $baseUrl): string {
    if ($rawUrl === '' || preg_match('/^(data:|blob:|javascript:|mailto:|#)/i', $rawUrl)) {
        return $rawUrl;
    }
    $resolved = resolveUrl($rawUrl, $baseUrl);

    // Unwrap search engine redirect URLs directly to the target page
    $parts = parse_url($resolved);
    if (!empty($parts['host']) && !empty($parts['query'])) {
        parse_str($parts['query'], $qParams);
        if (stripos($parts['host'], 'duckduckgo.com') !== false && ($parts['path'] ?? '') === '/l/' && !empty($qParams['uddg'])) {
            $resolved = $qParams['uddg'];
        } elseif (stripos($parts['host'], 'google.') !== false && ($parts['path'] ?? '') === '/url' && !empty($qParams['q'])) {
            $resolved = $qParams['q'];
        }
    }

    return 'proxy.php?url=' . urlencode($resolved);
}

// Rewrite HTML pages
if (stripos($contentType, 'text/html') !== false) {
    libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $dom->loadHTML('<?xml encoding="utf-8" ?>' . $body, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();

    $xpath = new DOMXPath($dom);

    // Remove meta CSP tags and Subresource Integrity attributes that block proxied scripts
    foreach ($xpath->query('//meta[translate(@http-equiv, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")="content-security-policy"]') as $meta) {
        $meta->parentNode->removeChild($meta);
    }

    foreach ($xpath->query('//*[@integrity]') as $el) {
        $el->removeAttribute('integrity');
    }

    foreach ($xpath->query('//*[@href]') as $el) {
        $el->setAttribute('href', toProxyUrl($el->getAttribute('href'), $finalUrl));
    }

    foreach ($xpath->query('//*[@src]') as $el) {
        $el->setAttribute('src', toProxyUrl($el->getAttribute('src'), $finalUrl));
    }

    foreach ($xpath->query('//*[@srcset]') as $el) {
        $entries = explode(',', $el->getAttribute('srcset'));
        $rewritten = array_map(function ($entry) use ($finalUrl) {
            $parts = preg_split('/\s+/', trim($entry));
            if (!empty($parts[0])) {
                $parts[0] = toProxyUrl($parts[0], $finalUrl);
            }
            return implode(' ', $parts);
        }, $entries);
        $el->setAttribute('srcset', implode(', ', $rewritten));
    }

    foreach ($xpath->query('//form') as $form) {
        $rawAction = $form->getAttribute('action') ?: $finalUrl;
        $resolvedAction = resolveUrl($rawAction, $finalUrl);
        $formMethod = strtolower($form->getAttribute('method') ?: 'get');

        $form->setAttribute('data-proxy-action', $resolvedAction);

        if ($formMethod === 'get') {
            $form->setAttribute('action', 'proxy.php');
            $hiddenInput = $dom->createElement('input');
            $hiddenInput->setAttribute('type', 'hidden');
            $hiddenInput->setAttribute('name', '__proxy_action');
            $hiddenInput->setAttribute('value', $resolvedAction);
            $form->appendChild($hiddenInput);
        } else {
            $form->setAttribute('action', 'proxy.php?url=' . urlencode($resolvedAction));
        }
    }

    // Inject fetch/XHR/form/beacon interceptor at the top of <head>
    $headNode = $dom->getElementsByTagName('head')->item(0);
    if (!$headNode && $dom->documentElement) {
        $headNode = $dom->createElement('head');
        $dom->documentElement->insertBefore($headNode, $dom->documentElement->firstChild);
    }

    if ($headNode) {
        $interceptorCode = '
        (function() {
            const TARGET_BASE = ' . json_encode($finalUrl) . ';
            const PROXY_BASE = new URL("proxy.php", window.location.href).pathname + "?url=";

            function toProxy(url) {
                if (!url || typeof url !== "string") return url;
                if (/^(data:|blob:|javascript:|mailto:|#)/i.test(url) || url.indexOf("proxy.php?url=") !== -1) {
                    return url;
                }
                try {
                    const resolved = new URL(url, TARGET_BASE).href;
                    return PROXY_BASE + encodeURIComponent(resolved);
                } catch (e) {
                    return url;
                }
            }

            const origFetch = window.fetch;
            window.fetch = function(input, init) {
                if (typeof input === "string") {
                    input = toProxy(input);
                } else if (input instanceof Request) {
                    input = new Request(toProxy(input.url), input);
                }
                return origFetch.call(this, input, init);
            };

            const origXhrOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url) {
                const args = Array.from(arguments);
                args[1] = toProxy(url);
                return origXhrOpen.apply(this, args);
            };

            const origWinOpen = window.open;
            window.open = function(url, target, features) {
                return origWinOpen.call(this, toProxy(url), target, features);
            };

            if (navigator.sendBeacon) {
                const origBeacon = navigator.sendBeacon.bind(navigator);
                navigator.sendBeacon = function(url, data) {
                    return origBeacon(toProxy(url), data);
                };
            }

            const origFormSubmit = HTMLFormElement.prototype.submit;
            HTMLFormElement.prototype.submit = function() {
                if ((this.method || "get").toLowerCase() === "get" && !this.querySelector("input[name=\'__proxy_action\']")) {
                    const input = document.createElement("input");
                    input.type = "hidden";
                    input.name = "__proxy_action";
                    input.value = this.getAttribute("data-proxy-action") || TARGET_BASE;
                    this.appendChild(input);
                    this.action = "proxy.php";
                }
                return origFormSubmit.apply(this, arguments);
            };
        })();
        ';

        $script = $dom->createElement('script');
        $script->appendChild($dom->createTextNode($interceptorCode));
        $headNode->insertBefore($script, $headNode->firstChild);
    }

    $output = $dom->saveHTML();
    echo str_replace('<?xml encoding="utf-8" ?>', '', $output);
    exit;
}

// Rewrite url(...) paths inside CSS files
if (stripos($contentType, 'text/css') !== false) {
    $body = preg_replace_callback('/url\(([\'"]?)(.*?)\1\)/i', function ($matches) use ($finalUrl) {
        return 'url(' . $matches[1] . toProxyUrl(trim($matches[2]), $finalUrl) . $matches[1] . ')';
    }, $body);
    echo $body;
    exit;
}

echo $body;
