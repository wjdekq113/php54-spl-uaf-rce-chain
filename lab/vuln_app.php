<?php
/**
 * Intentionally vulnerable fixture for the CVE-2015-6831 lab.
 *
 * Request body -> unserialize() -> count() -> normal request shutdown.
 *
 * The consumer intentionally avoids copying or rendering nested values. The
 * vulnerable zval is released during normal shutdown; changing the consumer
 * can change refcounts, destruction order, or whether the trigger is reached.
 *
 * Run only inside the disposable container supplied by this repository.
 */

header('Content-Type: text/plain; charset=utf-8');

$blob = file_get_contents('php://input');
if ($blob === false || $blob === '') {
    http_response_code(400);
    echo "no body\n";
    exit;
}

$rows = unserialize($blob);
if (!is_array($rows)) {
    http_response_code(422);
    echo "not a serialized array\n";
    exit;
}

echo "rows=", count($rows), "\n";
