// evidence reconstruction

$(document).ready(function() {

        // Event handler for table filtering or any action that changes the visibility of rows
//        $('#classFilter, #priorityFilter, #timeFilter').on('keyup', function() {
//            countVisibleLogs();
//        });

        // function to make button appear if at least one log item is selected

        $('#add_evirec_form').hide();
        // function below makes it so that on click it will add ToAdd to this class
        $('#logTable tbody tr').click(function(){
            if ($(this).hasClass("ToAdd")) {
                $(this).removeClass("ToAdd");
            } else {
                $(this).addClass("ToAdd");
            }

            makeAddModalAppear();

        });

        $('#add_evirec_form').submit(function(){
            var logIds = [];

            // Iterate over each row with class ToAdd
            $('#logTable tbody tr.ToAdd').each(function(){
                // get log id from first col
                var logid = $(this).find('td:first').text();
                logIds.push(logid);
            });

            //set value of hidden input field with log IDs as json
            $('#logIdsInput').val(JSON.stringify(logIds));

            return true;

        });



    });



function makeAddButtonAppear(){
    $('#EVIREC_BUTTON').hide();
    // if rows are selected to be added to evirec
    if ($('#logTable tbody tr.ToAdd').length) {
        // hide the button
        $('#EVIREC_BUTTON').show();
    }
}

function makeAddModalAppear(){
    $('#add_evirec_form').hide();
    // if rows are selected to be added to evirec
    if ($('#logTable tbody tr.ToAdd').length) {
        // hide the button
        $('#add_evirec_form').show();
    }
}



//function addToEvidencePathway() {
//      var table, tr, td, i;
//      table = document.getElementById("logTable");
//      tr = table.getElementsByTagName("tr");
//
//      for (i = 0; i < tr.length; i++) {
//            td = tr[i].getElementsByTagName("td")[2]; // Assuming "Class" is the third column (index 2)
//
//            if (td) {
//              if (td.innerHTML.toUpperCase().indexOf(filter) > -1) {
//                tr[i].style.display = "";
//              } else {
//                tr[i].style.display = "none";
//              }
//            }
//        }
//}