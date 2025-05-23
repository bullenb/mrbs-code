<?php
declare(strict_types=1);
namespace MRBS;


// Generates the HTML for a <script> element
function script_html(string $src, bool $add_version=false) : string
{
  $html = '<script src="';
  $value = ($add_version) ? add_version($src) : $src;
  $html .= escape_html($value);
  $html .= "\"></script>\n";

  return $html;
}


global $area;
global $multisite, $site;
global $debug;
global $custom_js_url;

$page = this_page(false, '.php');

// We need to construct a standard query string that can be passed to the *.js.php
// pages.  That's because some of the settings they use are area dependent.
// We also want the area to be in the query string so that the JavaScript page is
// cached if the area is the same and not otherwise.
$query_string = "area=$area";

if ($multisite && isset($site) && ($site !== ''))
{
  $query_string .= '&site=' . urlencode($site);
}

// Load the init file now so that it gets executed as soon as possible.  The init
// file can't use jQuery.
echo script_html('js/init.js.php', true);

echo script_html(($debug) ? 'jquery/jquery-3.7.1.js' : 'jquery/jquery-3.7.1.min.js');

// We need the migration script now that we are running jQuery 3.0+, or at least
// until we are confident that our JavaScript is not using any features that have
// been removed.   The uncompressed version will output warnings about removed and
// deprecated features to the console
echo script_html(($debug) ? 'jquery/jquery-migrate-3.5.0.js' : 'jquery/jquery-migrate-3.5.0.min.js');

// We are using the jQuery UI library, which has been custom-built to include the following components:
//   - Core
//      - as defined by dependencies in order to support the required interactions and widgets
//      - no need for jQuery 1.8 support
//
//   - Interactions
//      - Draggable
//      - Resizable
//
//   - Widgets
//      - Autocomplete
//      - Button
//      - Dialog
//      - Menu
//      - Mouse
//      - Tabs
//
//   - Cupertino theme
// If you need any other components you will need to rebuild the custom UI library
// See http://jqueryui.com/
echo script_html(($debug) ? 'jquery/ui/jquery-ui.js' : 'jquery/ui/jquery-ui.min.js', true);

// All pages
echo script_html("js/functions.js.php?$query_string", true);
echo script_html("js/general.js.php?$query_string", true);


echo script_html("js/flatpickr/flatpickr.min.js", true);
$datepicker_src = "js/datepicker.js.php?$query_string";
$flatpickr_lang_path = get_flatpickr_lang_path();
if (isset($flatpickr_lang_path))
{
  // Add the localisation file
  echo script_html($flatpickr_lang_path, true);
  // And give the datepicker file a query string parameter to force the browser cache
  // to be flushed when the language changes.
  $datepicker_src .= '&lang=' . urlencode(get_flatpickr_property($flatpickr_lang_path));
}
echo script_html($datepicker_src, true);

echo script_html("jquery/select2/dist/js/select2.full.min.js", true);

if (null !== ($select2_lang_path = get_select2_lang_path()))
{
  echo script_html($select2_lang_path, true);
}

// dataTables initialisation
if (in_array($page, array('admin', 'edit_users', 'pending', 'report', 'search', 'view_entry')))
{
  // Include the JavaScript for those pages that use dataTables
  // When constructing the DataTables download we want to include the following:
  //    DataTables styling framework
  //    DataTables package
  //    Buttons, and all sub-options
  //    ColReorder
  //    FixedColumns
  echo script_html(($debug) ? 'jquery/datatables/datatables.js' : 'jquery/datatables/datatables.min.js', true);
  echo script_html('jquery/datatables/plugins.js', true);
  echo script_html("js/datatables.js.php?$query_string", true);
}

// Get any page specific JavaScript
if (is_readable("js/$page.js"))
{
  echo script_html("js/$page.js?$query_string", true);
}
if (is_readable("js/$page.js.php"))
{
  echo script_html("js/$page.js.php?$query_string", true);
}

// The day, week and month views do refresh by Ajax.
// We need the resizable bookings for the day and week views
if ($page == 'index')
{
  echo script_html("js/refresh.js.php?$query_string", true);
  echo script_html("js/resizable.js.php?$query_string", true);
}

if (isset($custom_js_url))
{
  echo script_html($custom_js_url, true);
}

// Include the HTML5 Shiv so that elements such as <header> etc. can be styled in IE8 and below.
// (Even though we don't support IE8 and below, we still need the HTML5 Shiv for styling the
// page which says we don't support them!).
echo "<!--[if lte IE 8]>\n";
echo script_html(($debug) ? 'js/html5shiv.js' : 'js/html5shiv.min.js', true);
echo "<![endif]-->\n";
