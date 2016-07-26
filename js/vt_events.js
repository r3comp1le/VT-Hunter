function downloadFunc() {
    resp = "<div class='progress'><div class='progress-bar progress-bar-striped active' role='progressbar' aria-valuenow='100' aria-valuemin='0' aria-valuemax='100' style='width: 100%;'></div></div>";
    $("#load-bod").html(resp)
    $('#load_mod').modal('show');

    var md5s = []
    $("input:checkbox[name=selected]:checked").each(function(){
        md5 = this.id;
        md5s.push(md5);
    });
    thelink = '';

    $.ajax({
        type: "POST",
        url: "VT/vt_down.php",
        data : {md5Array : md5s},
        async: false,
        success: function(data){
            response = data;
            $('#load_mod').modal('hide');
            $("#modal-bod").html(response);
            $("#modal-title").html('Download Zip');
            $('#scrap_mod').modal('show');
        },
    });
}


function importEvent() {
    response = "<form><label for='md5'>Hashes (One per line!):</label><br>";
    response += "<textarea name='md5' id='importhash' placeholder='hashes and hashes and hashes'></textarea>";
    response += "<button type='button' class='btn btn-success' onclick='importFunc()'>";
    response += "Import</button></form>";
    $("#modal-bod").html(response);
    $("#modal-title").html("<h3>Import Events</h3");
    $("#scrap_mod").modal("show");
}

function importFunc() {
    var value = document.getElementById("importhash").value;
    $.ajax({
         type: "POST",
         url: "VT/vt_import_event.php",
         data: {md5s:value.split("\n")},
         success: function(data){
           console.log("Imported");
           console.log(data);
         },
         async: false
    });
}

function confirmDel(title) {
    response = "Are you sure you want to Delete?  <button type='button' class='btn btn-danger' onclick=\"deleteFunc()\">YES</button>";
    $("#modal-bod").html(response);
    $("#modal-title").html(title);
    $('#scrap_mod').modal('show');

}

function confirmArch(title, archStatus) {
    response = "Are you sure you want to " + archStatus + "?  <button type='button' class='btn btn-danger' onclick=\"archiveFunc('"+archStatus+"')\">YES</button>";
    $("#modal-bod").html(response);
    $("#modal-title").html(title);
    $('#scrap_mod').modal('show');
}

function deleteFunc() {
    $("input:checkbox[name=selected]:checked").each(function(){
        id = $(this).val();
        //console.log(id);
        delFunc(id);
    });
    $('#scrap_mod').modal('hide');
    location.reload();
}

function archiveFunc(archStatus) {
    $("input:checkbox[name=selected]:checked").each(function(){
        id = $(this).val();
        //console.log(id);
        if(archStatus=="Archive")
        {
            archFunc(id);
        }
        else
        {
            UnarchFunc(id)
        }
    });
    $('#scrap_mod').modal('hide');
    location.reload();
}

function delFunc(id) {
    trid = "#tr"+id;
    //console.log(trid);
    $.ajax({
        type: "POST",
        url: "VT/vt_del.php",
        data: {delId:id},
        success: function(data){
            if(data.trim() == "200")
            {
                removeRow(trid);
                //console.log("Deleted");
            }
            else
            {
                //console.log("Did not delete");
                //console.log(data);
            }
        },
        async:   false
    });
}
function archFunc(id) {
    console.log(id);
    trid = "#tr"+id;
    $.ajax({
        type: "POST",
        url: "VT/vt_archive.php",
        data: {archId:id},
        success: function(data){
            if(data.trim() == "archived")
            {
                removeRowA(trid);
                console.log("Archived");
            }
            else
            {
                console.log(data);
            }
        },
        async:   false
    });
}

function UnarchFunc(id) {
    console.log(id);
    trid = "#tr"+id;
    $.ajax({
        type: "POST",
        url: "VT/vt_unarchive.php",
        data: {archId:id},
        success: function(data){
            if(data.trim() == "unarchived")
            {
                removeRow(trid);
                console.log("UnArchived");
            }
            else
            {
                console.log(data);
            }
        },
        async:   false
    });
}

