<?php
header('Content-Type: text/plain');
echo "php_version=" . PHP_VERSION . "\n";
echo "sapi=" . php_sapi_name() . "\n";
echo "upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upload_progress.min_freq=" . ini_get('session.upload_progress.min_freq') . "\n";
echo "upload_progress.freq=" . ini_get('session.upload_progress.freq') . "\n";
echo "upload_progress.cleanup=" . ini_get('session.upload_progress.cleanup') . "\n";
echo "session.save_path=" . ini_get('session.save_path') . "\n";
echo "upload_max_filesize=" . ini_get('upload_max_filesize') . "\n";
echo "post_max_size=" . ini_get('post_max_size') . "\n";
