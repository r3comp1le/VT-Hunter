function runCrits(title) {

    resp = "<div class='progress'><div class='progress-bar progress-bar-striped active' role='progressbar' aria-valuenow='100' aria-valuemin='0' aria-valuemax='100' style='width: 100%;'></div></div>";
    $("#load-bod").html(resp)
    $('#load_mod').modal('show');

    $.ajax({
        type: "GET",
        url: "VT/vt_runCrits.php",
        async: false,
        success: function(response){
            $('#load_mod').modal('hide');
            $("#modal-bod").html(response);
            $("#modal-title").html(title);
            $('#scrap_mod').modal('show');
        },
    });

}

function runMISP(title) {

    resp = "<h3>Pulling from MISP...</h3><div class='progress'><div class='progress-bar progress-bar-striped active' role='progressbar' aria-valuenow='100' aria-valuemin='0' aria-valuemax='100' style='width: 100%;'></div></div>";
    $("#load-bod").html(resp)
    $('#load_mod').modal('show');

    $.ajax({
        type: "GET",
        url: "VT/vt_runMISP.php",
        async: false,
        success: function(response){
            $('#load_mod').modal('hide');
            $("#modal-bod").html(response);
            $("#modal-title").html(title);
            $('#scrap_mod').modal('show');
        },
    });

}

function runViper(title) {

    resp = "<div class='progress'><div class='progress-bar progress-bar-striped active' role='progressbar' aria-valuenow='100' aria-valuemin='0' aria-valuemax='100' style='width: 100%;'></div></div>";
    $("#load-bod").html(resp)
    $('#load_mod').modal('show');

    $.ajax({
        type: "GET",
        url: "VT/vt_runViper.php",
        async: false,
        success: function(response){
            $('#load_mod').modal('hide');
            $("#modal-bod").html(response);
            $("#modal-title").html(title);
            $('#scrap_mod').modal('show');
        },
    });

}
