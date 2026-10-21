<?php
$page = $_GET['page'] ?? '';
if ($page) { include($page); }
else { echo "LFI sim. Use ?page=/path"; }
