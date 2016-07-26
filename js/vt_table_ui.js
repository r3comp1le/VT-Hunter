function removeRow(trid) {
    var $killrow = $(trid);
    $killrow.addClass("danger");
    $killrow.fadeOut(1000, function(){$killrow.remove()});
}

function removeRowA(trid) {
    var $killrow = $(trid);
    $killrow.addClass("success");
    $killrow.fadeOut(1000, function(){$killrow.remove()});
}
function showlog(title) {
    jQuery.get('VT/vt.log', function(data) {
        $("#modal-bod").html(data)
        $("#modal-title").html(title);
        $('#scrap_mod').modal('show');
    });

}


function reloadData(title) {

    resp = "<h3>Pulling from VirusTotal...</h3><div class='progress'><div class='progress-bar progress-bar-striped active' role='progressbar' aria-valuenow='100' aria-valuemin='0' aria-valuemax='100' style='width: 100%;'></div></div>";
    $("#load-bod").html(resp)
    $('#load_mod').modal('show');

    $.ajax({
        type: "GET",
        url: "VT/vt_api_to_db.php",
        async: false,
        success: function(response){
            $('#load_mod').modal('hide');
            $("#modal-bod").html(response);
            $("#modal-title").html(title);
            $('#scrap_mod').modal('show');
        },
    });

}

function searchTag(tag) {
  $("#mytable").bootstrapTable("resetSearch", tag);
}

