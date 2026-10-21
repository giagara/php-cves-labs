<?php
header('Content-Type: text/plain');
echo "php_version=" . PHP_VERSION . "\n";
echo "sapi=" . php_sapi_name() . "\n";
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upload_progress.min_freq=" . ini_get('session.upload_progress.min_freq') . "\n";
echo "session.save_path=" . ini_get('session.save_path') . "\n";
echo "session.use_only_cookies=" . ini_get('session.use_only_cookies') . "\n";
echo "session.serialize_handler=" . ini_get('session.serialize_handler') . "\n";
