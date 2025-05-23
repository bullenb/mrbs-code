<?php
namespace MRBS;

// Update the area table getting rid of NULLs for enable_periods and replacing them
// with the default setting.

global $enable_periods;

// Convert booleans to 1 or 0, as the fields are tinyints/smallints
$value = ($enable_periods) ? 1 : 0;

$upgrade_handle->command("UPDATE " . _tbl('area') . " SET enable_periods=$value WHERE enable_periods IS NULL");
