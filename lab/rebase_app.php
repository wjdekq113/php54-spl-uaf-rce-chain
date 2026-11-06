<?php
/* Local-only output fixture for the leak/read/rebase chain. */
$blob = file_get_contents('php://input');
$rows = unserialize($blob);

header('Content-Type: text/plain; charset=us-ascii');
echo "CELL_BEGIN\n";
if (is_string($rows[0][0])) {
    echo bin2hex($rows[0][0]);
} else {
    echo $rows[0][0];
}
echo "\nCELL_END\n";
