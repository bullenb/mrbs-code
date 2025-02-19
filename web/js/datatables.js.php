<?php
declare(strict_types=1);
namespace MRBS;

require "../defaultincludes.inc";

http_headers(array("Content-type: application/x-javascript"),
  60*30);  // 30 minute expiry

// See https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.spreadsheet.pagesetup?view=openxml-2.8.1
define('EXCEL_PAGE_SIZES', array(
  1 =>  'LETTER',
  3 =>  'TABLOID',
  5 =>  'LEGAL',
  8 =>  'A3',
  9 =>  'A4',
  11 => 'A5'
));

// Get the Excel paper size constant.  If the config setting hasn't been set for some reason choose
// a suitable default.  Otherwise if it's one of the predefined strings get its value, or else just
// use the value itself.
if (!isset($excel_default_paper))
{
  $excel_paper_size = array_search('A4', EXCEL_PAGE_SIZES);
}
elseif ((in_arrayi($excel_default_paper, EXCEL_PAGE_SIZES)))
{
  $excel_paper_size = array_search($excel_default_paper, EXCEL_PAGE_SIZES);
}
else
{
  $excel_paper_size = $excel_default_paper;
}
?>

'use strict';

<?php
// Actions to take once the datatable's initialisation is complete.
// Remember that some of the table initialisation operations, eg loading of the
// language file, are asynchronous.
?>
var initCompleteActions = function initCompleteActions(dataTable) {
  <?php // Make the table visible ?>
  $('.datatable_container').css('visibility', 'visible');
  <?php // Need to adjust column sizing after the table is made visible ?>
  dataTable.columns.adjust();
}

<?php
// Get the types, which are assumed to be in a data-type in a <span> in the <th>
// of the table
?>
var getTypes = function getTypes(table) {
    var type,
        types = {},
        result = [];

    table.find('thead tr:first th').each(function(i) {
       var type = $(this).find('span').data('type');

       if (type)
       {
         if (types[type] === undefined)
         {
           types[type] = [];
         }
         types[type].push(i);
       }
      });

    for (type in types)
    {
      if (types.hasOwnProperty(type))
      {
        result.push({type: type,
                     targets: types[type]});
      }
    }

    return result;
  };


<?php
// Extract email addresses from mailto: links in the columns defined by columnSelector and
// copy them to the clipboard, optionally sorting the result.
?>
var extractEmailAddresses = function(dt, columnSelector, sort) {
  var result = [];
  var message;
  const scheme = 'mailto:';

  $.each(dt.columns(columnSelector).data(), function (i, column) {
    $.each(column, function (j, value) {
      try {
        var valueObject = $(value);
        <?php // Need to search for an href in both this element and its descendants ?>
        var href = valueObject.find('a').add(valueObject.filter('a')).attr('href');
        if ((href !== undefined) && href.startsWith(scheme)) {
          var address = href.substring(scheme.length);
          if ((address !== '') && !result.includes(address)) {
            result.push(address);
          }
        }
      } catch (error) {
        <?php
        // No need to do anything. This will catch the cases when $(value) fails because
        // value is not a valid anchor element, and so we are not interested in it anyway.
        ?>
      }
    });
  });

  if (sort) {
    result.sort();
  }

  navigator.clipboard.writeText(result.join(', '))
    .then(() => {
      message = '<?php echo get_js_vocab('unique_addresses_copied')?>';
      message = message.replace('%d', result.length.toString());
    })
    .catch((err) => {
      message = '<?php echo get_js_vocab('clipboard_copy_failed')?>';
      console.error(err);
    })
    .finally(() => {
      dt.buttons.info(
        dt.i18n('buttons.copyTitle', 'Copy to clipboard'),
        message,
        2000
      )
    });
};


var customizeExcel = function(xlsx) {
  <?php // See https://datatables.net/forums/discussion/45277/modify-page-orientation-in-xlxs-export ?>
  var sheet = xlsx.xl.worksheets['sheet1.xml'];
  var pageSetup = sheet.createElement('pageSetup');
  sheet.childNodes['0'].appendChild(pageSetup);
  var settings = sheet.getElementsByTagName('pageSetup')[0];
  settings.setAttribute("r:id", "rId1"); <?php // Relationship ID - do not change ?>
  settings.setAttribute('orientation', '<?php echo $excel_default_orientation ?>');
  settings.setAttribute('paperSize', '<?php echo $excel_paper_size ?>');
};

<?php
// Turn the table with id 'id' into a DataTable, using specificOptions
// which are merged with the default options.  If the buttons property is
// set in specificOptions then the first element in the array should be the
// colvis button and any other elements are extra buttons.
//
// fixedColumnsOptions is an optional object that gets passed directly to the
// DataTables FixedColumns constructor
//
// If you want to do anything else as part of fnInitComplete then you'll need
// to define fnInitComplete in specificOptions
?>

function makeDataTable(id, specificOptions, fixedColumnsOptions)
{
  var i,
      defaultOptions,
      mergedOptions,
      colVisIncludeCols,
      nCols,
      table,
      dataTable,
      fixedColumns;

  var buttonCommon = {
      exportOptions: {
        columns: ':visible',
        format: {
          body: function (data, row, column, node) {
            var div = $('<div>' + data + '</div>');
            <?php
            // Remove any elements used for sorting, which are all <span>s that don't
            // have a class of 'normal' (which the CSS makes visible). Note that we cannot
            // just remove :hidden elements because that would also remove everything that's
            // not on the current page and visible on screen.
            // (We can get rid of this step when we move to using orthogonal data.)
            ?>
            div.find('span:not(.normal)').remove();
            <?php // Apply the default export data stripping ?>
            var result = $.fn.dataTable.Buttons.stripData(div.html());
            <?php
            // If that is the empty string then it may be that the data is actually a form
            // and the text we want is the text in the submit button.
            ?>
            if (result === '')
            {
              var value = div.find('input[type="submit"]').attr('value');
              if (value !== undefined)
              {
                result = value;
              }
            }
            return result;
          }
        }
      }
    };

  table = $(id);
  if (table.length === 0)
  {
    return false;
  }

  <?php
  // Remove the <colgroup>.  This is only needed to assist in the formatting
  // of the non-datatable version of the table.   When we have a datatable,
  // the datatable sorts out its own formatting.
  ?>
  table.find('colgroup').remove();

  <?php
  // In the latest releases of DataTables a CSS rule of 'width: 100%' does not work with FixedColumns.
  // Instead you have to either set a style attribute of 'width: 100%' or set a width attribute of '100%'.
  // The former would cause problems with sites that have a Content Security Policy of "style-src 'self'" -
  // though this is a bit academic since DataTables contravenes it anyway, but maybe things will change
  // in the future.  The latter isn't ideal either because 'width' is a deprecated attribute, but we set
  // the width attribute here as the lesser of two evils.
  ?>
  table.attr('width', '100%');

  <?php // Set up the default options ?>
  defaultOptions = {
    buttons: [{extend: 'colvis',
               text: '<?php echo get_js_vocab("show_hide_columns") ?>'}],
    deferRender: true,
    lengthMenu: [ [10, 25, 50, 100, -1], [10, 25, 50, 100, '<?php echo get_js_vocab('dt_all') ?>'] ],
    paging: true,
    pageLength: 25,
    pagingType: 'full_numbers',
    processing: true,
    scrollCollapse: true,
    stateSave: <?php echo (empty($state_save)) ? 'false' : 'true' ?>,
    stateDuration: <?php echo $state_duration ?? 0 ?>,
    dom: 'B<"clear">lfrtip',
    scrollX: '100%',
    colReorder: {}
  };

  <?php
  // Make room for any extra buttons after the first button, which is assumed
  // to be the colvis button.
  ?>
  if (specificOptions && specificOptions.buttons)
  {
    for (i=0; i<specificOptions.buttons.length - 1; i++)
    {
      defaultOptions.buttons.push({});
    }
  }

  <?php
  // For all pages except the pending page, which has collapsible rows which don't work well with the
  // buttons, add the Copy/CSV/etc. buttons.
  ?>
  if (args.page !== 'pending')
  {
    defaultOptions.buttons = defaultOptions.buttons.concat(
      $.extend(true, {}, buttonCommon, {
        extend: 'copy',
        text: '<?php echo get_js_vocab('copy') ?>'
      }),
      $.extend(true, {}, buttonCommon, {
        extend: 'csv',
        text: '<?php echo get_js_vocab('csv') ?>'
      }),
      $.extend(true, {}, buttonCommon, {
        extend: 'excel',
        text: '<?php echo get_js_vocab('excel') ?>',
        customize: customizeExcel
      }),
      $.extend(true, {}, buttonCommon, {
        <?php
        // Use 'pdfHtml5' rather than 'pdf'.  See
        // https://github.com/meeting-room-booking-system/mrbs-code/issues/3512
        ?>
        extend: 'pdfHtml5',
        text: '<?php echo get_js_vocab('pdf') ?>',
        orientation: '<?php echo $pdf_default_orientation ?>',
        pageSize: '<?php echo $pdf_default_paper ?>'
      }),
      $.extend(true, {}, buttonCommon, {
        extend: 'print',
        text: '<?php echo get_js_vocab('print') ?>'
      })
    );
  }

  <?php
  // Set the language file to be used
  if ($lang_file = get_datatable_lang_path())
  {
    ?>
    defaultOptions.language = {url: '<?php echo "./$lang_file" ?>'}
    <?php
  }
  ?>


  <?php
  // Construct the set of columns to be included in the column visibility
  // button.  If specificOptions is set then use that.  Otherwise include
  // all columns except any fixed columns.
  ?>
  if (specificOptions &&
      specificOptions.buttons &&
      specificOptions.buttons[0] &&
      specificOptions.buttons[0].columns)
  {
    defaultOptions.buttons[0].columns = specificOptions.buttons;
  }
  else
  {
    colVisIncludeCols = [];
    nCols = table.find('tr:first-child th').length;
    for (i=0; i<nCols; i++)
    {
      if (fixedColumnsOptions)
      {
        if (fixedColumnsOptions.leftColumns && (i < fixedColumnsOptions.leftColumns))
        {
          continue;
        }
        if (fixedColumnsOptions.rightColumns && (i >= nCols-fixedColumnsOptions.rightColumns))
        {
          continue;
        }
      }
      colVisIncludeCols.push(i);
    }
    defaultOptions.buttons[0].columns = colVisIncludeCols;
  }

  defaultOptions.initComplete = initCompleteActions;

  <?php
  // Merge the specific options with the default options.  We do a deep
  // merge.
  ?>
  mergedOptions = $.extend(true, {}, defaultOptions, specificOptions);
  // Merge the initComplete properties, if any of them are set.  This has to be
  // done separately as they are functions.
  if (defaultOptions.initComplete || specificOptions.initComplete) {
    mergedOptions.initComplete = function () {
      if (defaultOptions.initComplete) {
        defaultOptions.initComplete.call(this, dataTable);
      }
      if (specificOptions.initComplete) {
        specificOptions.initComplete.call(this);
      }
    };
  }

  <?php // Localise the sorting.  See https://datatables.net/blog/2017-02-28 ?>
  $.fn.dataTable.ext.order.intl($('body').data('langPrefs'));

  dataTable = table.DataTable(mergedOptions);

  if (fixedColumnsOptions)
  {
    fixedColumns = new $.fn.dataTable.FixedColumns(dataTable, fixedColumnsOptions);
  }

  <?php
  // If we're using an Ajax data source then don't offer column reordering.
  // This is a problem at the moment in DataTables because if you reorder a column
  // DataTables doesn't know that the Ajax data is still in the original order.
  // May be fixed in a future release of DataTables
  ?>
  if (!specificOptions.ajax)
  {
    <?php
    /*
    // In fact we don't use column reordering at all, because (a) it doesn't
    // work with an Ajax source (b) there's no way of fixing the right hand column
    // (c) iFixedColumns doesn't seem to work properly and (d) it's confusing
    // for the user having reordering enabled sometimes and sometimes not.  Better
    // to wait for a future release of DataTables when these issues have been
    // fixed.  In the meantime the line of code we need is there below so we can see
    // how it is done, but commented out.

    var oCR = new ColReorder(oTable, mergedOptions);

    */
    ?>
  }

  <?php
  // Adjust the column sizing on a window resize.   We shouldn't have to do this because
  // columns.adjust() is called automatically by DataTables on a window resize, but if we
  // don't then a right hand fixed column appears twice when a window's width is increased.
  // I have tried to create a simple test case, but everything works OK in the test case, so
  // it's something to do with the way MRBS uses DataTables - maybe the CSS, or maybe the
  // JavaScript.
  ?>
  $(window).on('resize', function () {
    dataTable.columns.adjust();
  });

  return dataTable;

}
