<?php
header('Content-Type: text/plain');
$sid = $_GET['sid'] ?? '';
if (!$sid) {
    echo "usage: ?sid=<session_id>\n";
    $files = glob(ini_get('session.save_path') . '/sess_*');
    echo "sessions on disk: " . count($files) . "\n";
    foreach ($files as $f) {
        echo basename($f) . " " . filesize($f) . "B\n";
    }
    exit;
}
$path = ini_get('session.save_path') . '/sess_' . basename($sid);
if (file_exists($path)) {
    echo "=== sess_" . basename($sid) . " ===\n";
    echo file_get_contents($path) . "\n";
} else {
    echo "session file not found\n";
}
