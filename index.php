<?
require('VT/config.php');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VT Hunter</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" crossorigin="anonymous">
    
    <script src="js/jquery.js"></script>
    <script src="js/jquery-migrate.js"></script>
    <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.11.0/bootstrap-table.min.css">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==" crossorigin="anonymous"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.js"></script>

</head>

<body>
<style>
    .modal-content {
    width: 900px;
    margin-left: -150px;
    }
    textarea{
    width: 870px;
    height: 300px;
    }

   .filenames {
      font-family: monospace !important;
    }
    mark {
    background-color: red;
    color: black;
    }
    .modal-header {
    padding:9px 15px;
    }
    .container{
        width: 100%;
    }
    .progress-bar.animate {
        width: 100%;
    }

    td {
      padding: 2px -15px 2px 2px !important;
    }
}
</style>

<script>
function toggle(source) {
    checkboxes = document.getElementsByName('selected');
    for(var i=0, n=checkboxes.length;i<n;i++) {
        checkboxes[i].checked = source.checked;
    }
}

function launch_info_modal(id, title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

            behaviour_dns = "";
            behaviour_http = "";
            url = "";
            sample_info = "";
            alert_info = "";
            debug_name = "";
            debug_signature = "";
            tags = "";

            alert_info =
            "<span class='label label-primary'>Sample Details</span>" +
            "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>MD5</th><td><a href='https://www.virustotal.com/intelligence/search/?query="+ data.md5 +"#md5'>" + data.md5 + "</a></td></tr>" +
                  "<tr><th>SHA1</th><td>" + data.sha1 + "</td></tr>" +
                  "<tr><th>SHA256</th><td>" + data.sha256 + "</td></tr>" +
                  "<tr><th>First Seen</th><td>" + data.first_seen + "</td></tr>" +
                  "<tr><th>Last Seen</th><td>" + data.last_seen + "</td></tr>" +
                  "<tr><th>File Type</th><td>" + data.type + "</td></tr>" +
                  "<tr><th>Size</th><td>" + data.size + "</td></tr>" +
                "</tbody>" +
              "</table>";

            if(typeof data.sample_info !== 'undefined')
            {
            trid = data.trid.replace(/\n/g, '<br>');
            try {
                for (i = 0; i < data.behaviour_dns.length; i++)
                {
                    behaviour_dns +=
                    JSON.stringify(data.behaviour_dns[i].ip) +" : " + JSON.stringify(data.behaviour_dns[i].hostname) +"<br>" ;
                }

                for (i = 0; i < data.behaviour_http.length; i++)
                {
                    behaviour_http += JSON.stringify(data.behaviour_http[i].url) +"<br>";
                }

                for (var urls in data.ITW_urls)
                {
                    url += urls + " : " + data.ITW_urls[urls] + "<br>";
                }

                for (var debugs in data.pe_debug['codeview'])
                {
                    debug_name = debugs['name'] + "<br>";
                    debug_signature = debugs['signature'] + "<br>";
                }

                for (i = 0; i < data.tags.length; i++)
                {
                    tags += data.tags[i] + ", ";
                }
            }
            catch(err)
            {
                console.log(err.message);
            }

            sample_info =
            "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>Authentihash</th><td>" + data.authentihash + "</td></tr>" +
                  "<tr><th>Import Hash</th><td><a href='https://www.virustotal.com/intelligence/search/?query=imphash:\""+ data.imphash +"\"'>" + data.imphash + "</a></td></tr>" +
                  "<tr><th>SSDeep</th><td><a href='https://www.virustotal.com/intelligence/search/?query=ssdeep:%22"+ data.ssdeep +" 40%22'>VT Link</a></td></tr>" +
                  "<tr><th>Submission Names</th><td>" + data.submission_names + "</td></tr>" +
                  "<tr><th>Time Submitted</th><td>" + data.times_submitted + "</td></tr>" +
                  "<tr><th>Timestamp</th><td>" + data.timestamp + "</td></tr>" +
                  "<tr><th>Packer</th><td>" + data.unpacker + "</td></tr>" +
                  "<tr><th>Magic</th><td>" + data.magic + "</td></tr>" +
                  "<tr><th>Tags</th><td>" + tags + "</td></tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>SigCheck</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>Publishers</th><td>" + data.sigcheck_pub + "</td></tr>" +
                  "<tr><th>Verified</th><td>" + data.sigcheck_verified + "</td></tr>" +
                  "<tr><th>Date</th><td>" + data.sigcheck_date + "</td></tr>" +
                  "<tr><th>Signers</th><td>" + data.sigcheck_signers + "</td></tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>TRID</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>" + trid + "</td></tr>" +
                "</tbody>" +
              "</table>" +

              "<span class='label label-primary'>PE Debug</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>Name</td><td>"+debug_name+"</tr>" +
                  "<tr><td>Signature</td><td>"+debug_signature+"</tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>Exif</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>TimeStamp</th><td>" + data.exif_TimeStamp + "</td></tr>" +
                  "<tr><th>Language</th><td>" + data.exif_LanguageCode + "</td></tr>" +
                  "<tr><th>File Name</th><td>" + data.exif_OriginalFileName + "</td></tr>" +
                  "<tr><th>Internal Name</th><td>" + data.exif_InternalName + "</td></tr>" +
                  "<tr><th>Product Name</th><td>" + data.exif_ProductName + "</td></tr>" +
                  "<tr><th>Company Name</th><td>" + data.exif_company + "</td></tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>Behaviour</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>UDP</td><td>"+data.behaviour_upd+"</tr>" +
                  "<tr><td>HTTP</td><td>"+behaviour_http+"</tr>" +
                  "<tr><td>DNS</td><td>"+behaviour_dns+"</tr>" +
                  "<tr><td>TCP</td><td>"+data.behaviour_tcp+"</tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>ITW</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>"+url+"</tr>" +
                "</tbody>" +
              "</table>";
            }


        $("#modal-title").html(title);
        $("#modal-bod").html(
            alert_info +
            sample_info
            );

        $('#scrap_mod').modal('show');
        },
    });
}

function launch_yara_modal(id, title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

        yara = data.match;
        yara0 = yara.replace(/\n/g, "<br>");
        yara1 = yara0.replace(/\*begin_highlight*/g, "<mark>");
        yara2 = yara1.replace(/\*end_highlight*/g, "</mark>");

        $("#modal-bod").html(yara2);
        $("#modal-title").html(title + ' (' + data.date + ')');
        $('#scrap_mod').modal('show');

        },
    });
}

function launch_av_modal(id,title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

        var av = "";

        for (x in data.scans)
        {
            if(data.scans[x] != null){av += "<b>"+x+"</b>" + ":" + data.scans[x] + "<br>";}
        }

        $("#modal-bod").html(av);
        $("#modal-title").html(title);
        $('#scrap_mod').modal('show');
        },
    });
}

function conn_test(source){
    $.ajax({
        type: "POST",
        url: "VT/conn_test.php",
        data: {source:source},
        success: function(data){
            alert(data);
        },
    });
}

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
    response = "<form><label for='md5'>MD5 (One per line!):</label>";
    response += "<textarea name='md5' id='importhash' placeholder='hashes'></textarea>";
    response += "<button type='button' class='btn btn-success' onclick='importFunc()'>";
    response += "Import</button></form>";
    $("#modal-bod").html(response);
    $("#modal-title").html("<h3>Import Event</h3");
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

function addTag(id) {
    var tags;
    $.ajax({
      type: "GET",
      url: "VT/vt_get_tags.php",
      success: function(data) { console.log(data); tags = JSON.parse(data); },
      async: false
    });
    resp = "<input type='hidden' id='test' value='"+id+"'></input>";
    for (var i = 0; i < tags.length; i++) {
      resp += "<span style='color: "+tags[i]["colour"]+"'>" 
      resp += "<button type='button' class='btn' ";
      resp += "onclick='addTheTag(\"" + tags[i]["name"] + "\")'>"
      resp += "<h4>"+tags[i]["name"]+"</h4></button><br>";
      resp += "</span>"
    }
    resp += "<br><br><h4>Or create a new tag:</h4><br>";
    resp += "<input placeholder='Tag Name' id='cmnt' ></input><br>";
    resp += "<style> .inlinepicker { display: inline-block; }</style>";
    resp += "<label for='clr'>Colour:</label><input value='#00ff00' id='colorpick'></input>"
    resp += "<button type='button' class='btn btn-success' ";
    resp += "onclick='addATag("+id+")'>Create</button>";
    $("#modal-bod").html(resp);
    $("#modal-title").html("<h3>Add a tag</h3>");
    $('#scrap_mod').modal('show');

}

function addTheTag(name, id) {
  if (id == null)
    var id = document.getElementById("test").value;
  console.log(id + ", " + name);
  $.ajax({
      type: "POST",
      url: "VT/vt_modify_tag.php",
      data: {tag:name, id:id},
      success: function(data) {
        console.log(data);
        //location.reload();
      },
      async: true
    });
    location.reload();
}

function addATag(id) {
    var val = document.getElementById("cmnt").value;
    var col = document.getElementById("colorpick").value;
    console.log("Adding "+val+" to "+id);
    $.ajax({
      type: "POST",
      url: "VT/vt_add_tag.php",
      data: {colour:col, name:val},
      success: function(data) {
        console.log(data);
        $('#load_mod').modal('hide');

      },
      async: false
    });
    addTheTag(val, id);
    location.reload();
}

function removeTag(id, tag) {
  console.log("Removing " + tag + " from " + id);

  $.ajax({
    type: "POST",
    url: "VT/vt_remove_tag.php",
    data: {id: id, tag:tag},
    async: false,
    success: function(data) {
      console.log(data);
    }
  });

  location.reload();
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

function showConfig(title) {
    response = "<?
    #Mongo
    print "<b>Mongo Server</b>: " . $mongo_server_host . "<br>";
    print "<b>Mongo Port</b>: " . $mongo_server_port . "<br>";
    print "<b>Mongo DB</b>: " . $mongo_db . "<br>";
    print "<b>Mongo Collection</b>: " . $mongo_collection . "<br>";
    print "<button type='button' class='btn btn-primary btn-xs' onclick='conn_test(&#39;mongo&#39;)'>Test Connection</button><br>";
    print "<br>";

    #Crits Connections
    print "<b>Crits Integration</b>: " . $crits_on . "<br>";
    print "<b>Crits URL</b>: " . $crits_url . "<br>";
    print "<button type='button' class='btn btn-primary btn-xs' onclick='conn_test(&#39;crits&#39;)'>Test Connection</button><br>";
    print "<br>";
	
	#Viper Connections
    print "<b>Viper Integration</b>: " . $viper_on . "<br>";
    print "<b>Viper URL</b>: " . $viper_api_url . "<br>";
    print "<button type='button' class='btn btn-primary btn-xs' onclick='conn_test(&#39;viper&#39;)'>Test Connection</button><br>";
    print "<br>";
	
	#MISP Connections
    print "<b>MISP Integration</b>: " . $misp_on . "<br>";
    print "<b>MISP URL</b>: " . $misp_url . "<br>";
    print "<button type='button' class='btn btn-primary btn-xs' onclick='conn_test(&#39;misp&#39;)'>Test Connection</button><br>";
    print "<br>";

    #VT
    print "<b>VT Alerts</b>: " . $vt_mal . "<br>";
    print "<b>VT Search</b>: " . $vt_search . "<br>";
    print "<b>Delete Alerts from VT</b>: " . $delete_alerts . "<br>";
    print "<button type='button' class='btn btn-primary btn-xs' onclick='conn_test(&#39;vt&#39;)'>Test Connection</button><br>";
    print "<br>";

    print "<b>AV Multi</b>: " . $av_multiple . "<br>";
    print "<b>Manual Pull</b>: " . $manual_pull . "<br>";

    ?>";
    $("#modal-bod").html(response);
    $("#modal-title").html(title);
    $('#scrap_mod').modal('show');
}

function reloadPage(){
    location.reload();
}

jQuery(document).ready(function($){
    $('[data-toggle="tooltip"]').tooltip();
});

function idSorter(a,b){
    if (a.id < b.id) return -1;
    if (a.id > b.id) return 1;
    return 0
}

function tagsorter(a, b) {
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}
</script>

<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <a class="navbar-brand" href="index.php">VT Hunter</a>
      <a class="navbar-brand" href="index.php?archive=true">Archived</a>
      <a class="navbar-brand" href="about.php">About</a>
    </div>
  </div>
</nav>

<div class="container">
<br><br><br><br>
<?
try
{
    $m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
    $db = $m->selectDB($mongo_db);
    $collection = new MongoCollection($db, $mongo_collection);
}
catch ( MongoConnectionException $e )
{
    echo $e;
    die();
    echo '<div class="alert alert-block alert-danger fade in"><button data-dismiss="alert" class="close close-sm" type="button"><i class="icon-remove"></i></button>Can\'t Connect to Mongo</div>';
    exit();
}

#Chec Archived Option
if(isset($_GET['archive']) && $_GET['archive'] == 'true')
{
	$archStatus = "Unarchive";
    $archQuery = array('archive' => 'true');
}
else
{
	$archStatus = "Archive";
    $archQuery = array('archive' => null);
}
$cursor = $collection->find($archQuery);
$cursor->sort(array("date" => -1));
?>
<div class="btn-group">
<button class="btn btn-info" type="button">Alerts <span class="badge"><?print $cursor->count();?></span></button>
</div>

<div class="btn-group">
  <button type="button" class="btn btn-primary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Download<span class="caret"></span>
  </button>
  <ul class="dropdown-menu">
    <li onclick="downloadFunc('Download')"><a>MD5</a></li>
  </ul>
</div>

<!-- Add a custom event from VT -->
<div class="btn-group">
  <button type='button' class='btn btn-info' data-toggle='tooltip'
          data-placement='top' title='Add a new event from VT'
          onclick='importEvent()'>
      Import
  </button>
</div>

<div class="btn-group">
  <button type='button' class='btn btn-danger' data-toggle='tooltip' 
          data-placement='top' title='Delete from DB' 
          onclick="confirmDel('Delete')">Delete</button>
</div>

<div class="btn-group">
	<button type='button' class='btn btn-success' data-toggle='tooltip' data-placement='top' title='<? echo $archStatus ?> Selected' onclick="confirmArch('Archive','<?echo $archStatus ?>')"><? echo $archStatus ?></button>
</div>
	
<div class="btn-group">
  <button type="button" class="btn btn-warning dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Settings<span class="caret"></span>
  </button>
  <ul class="dropdown-menu">
    <li onclick="showlog('Log')"><a data-toggle='tooltip' data-placement='top' title='Show Log'>Log</a></li>
    <li onclick="showConfig('Config')"><a data-toggle='tooltip' data-placement='top' title='Show Config'>Config</a></li>
    <? if($manual_pull == "true")
    {
        print "<li onclick=\"reloadData('VT Sync')\"><a data-toggle='tooltip' data-placement='top' title='Get Alerts from VT'>Pull VT</a></li>";
		print "<li role='separator' class='divider'></li>";
        if($crits_on == "true")
        {
            print "<li onclick=\"runCrits('Crits Lookup')\"><a data-toggle='tooltip' data-placement='top' title='Crits Lookup'>Pull Crits</a></li>";
        }
		if($misp_on == "true")
        {
            print "<li onclick=\"runMISP('MISP Lookup')\"><a data-toggle='tooltip' data-placement='top' title='Crits Lookup'>Pull MISP</a></li>";
        }
		if($viper_on == "true")
        {
            print "<li onclick=\"runViper('Viper Lookup')\"><a data-toggle='tooltip' data-placement='top' title='Viper Lookup'>Pull Viper</a></li>";
        }
    }
    ?>
  </ul>
</div>

<div id="filter-bar"> </div>
<table id='mytable' data-toggle="table" data-classes="table table-hover table-condensed" data-striped="true" data-show-columns="true" data-search="true" data-pagination="true" data-page-size="20">
<thead>
<tr>
  <th data-field="check" data-sortable="false"><input type="checkbox" onClick="toggle(this)"/> All<br/></th>
  <th data-field="num" data-sortable="true" data-sorter="idSorter" data-sort-name="_num_data">Details</th>
  <th data-field="rule" data-sortable="true">Rule</th>
  <th data-field="md5" data-sortable="true">MD5</th>
  <th data-field="filename" data-sortable="true">FileName</th>
  <? 
  if($crits_on == "true")
  {
    print "<th data-field='crits' data-sortable='true'>CRITS</th>";
  }
  if($misp_on == "true")
  {
    print "<th data-field='crits' data-sortable='true'>MISP</th>";
  }
  if($viper_on == "true")
  {
    print "<th data-field='crits' data-sortable='true'>Viper</th>";
  }
  ?>
  <th data-field="tag" data-sortable="true" data-sorter="tagsorter">Tags</th>
  <th data-field="seen" data-sortable="true">First Seen</th>
  <th data-field="compile" data-sortable="true">Compile</th>
  <th data-field="av" data-sortable="true" data-sorter="idSorter" data-sort-name="_av_data">AV</th>
  <? if($av_multiple == "true")
  {
      print "<th data-field='av_vendor' data-sortable='true'>AV Description</th>";
  }
  else
  {
      print "<th data-field='av_vendor' data-sortable='true'>" . $av_vendor . "</th>";
  }?>
  <th data-field="size" data-sortable="true">Size</th>
  <th data-field="Type" data-sortable="true">Type</th>
  <th data-field="id" data-sortable="false">Action</th>
</tr>
</thead>
<tbody>
<?
$int = 1;

foreach ($cursor as $array)
{
    if (isset($array['archive'])){
        if($array['archive'] == true){print "<tr class='success' id='tr".number_format($array['id'],0,'.','')."'>";}else{print "<tr id='tr".number_format($array['id'],0,'.','')."'>";}
    }
    else
    {
        print "<tr id='tr".number_format($array['id'],0,'.','')."'>";
    }
    print "<td><input type='checkbox' name='selected' id='".$array['md5']."' value='".number_format($array['id'],0,'.','')."'/></td>";
    print "<td data-id='".$int."'><button type='button' class='btn btn-info btn-xs' data-toggle='tooltip' data-placement='top' title='Sample Details' onclick=\"launch_info_modal(".number_format($array['id'],0,'.','').",'Details')\">Event ".$int."</button><br><button type='button' class='btn btn-warning btn-xs' data-toggle='tooltip' data-placement='top' title='Yara Results' onclick=\"launch_yara_modal(".number_format($array['id'],0,'.','').",'Yara')\">".$array['ruleset_name']."</button></td>";
    print "<td>".$array['subject']."</td>";
    print "<td id='md5'><a href='https://www.virustotal.com/intelligence/search/?query=".$array['sha256']."' target='_blank'>".$array['md5']."</a>";
    if(!empty($array['url'])){print "<span class='label label-default'>ITW</span>";}
    if(!empty($array['behaviour_dns'])){print "<span class='label label-default'>C2</span>";}
    print "</td>";
	print "<td>";
  print "<div class='filenames'>";
  $submission = $array["submission_names"];

  print ((strlen($submission[0]) > 20)? substr($submission[0],0,20)."...":$submission[0]) ;

  if (count($submission) > 1) {
    $modifier = 0;
    if (strpos($submission[0], "_")) $modifier = 1;
    $padding = min(23, strlen($submission[0]));
    for ($i = 0; $i < 30-$padding; $i++) echo "&nbsp";
	  print("<button type='button' class='btn btn-xs btn-info' data-toggle='collapse' data-target='#names-{$array['id']}'><i class='glyphicon glyphicon-menu-down'></i></button>");

    print("<div  class='collapse' id='names-{$array['id']}'>");
    foreach (array_slice($array['submission_names'], 1) as $filename)
	  {
	    print ((strlen($filename) > 30)? substr($filename,0,30)."...":$filename) . "<br>";
	  }
  }
  print("</div>");
  print("</div>");
	print "</td>";
    # Crits check
    if ($crits_on == "true")
    {
      if (isset($array['crits']))
      {
          if($array['crits'] == "true")
          {
              print "<td><a href='".$crits_url."/samples/details/".$array['md5']."' target='_blank'>Crits</a></td>";
          }
          else
          {
              print "<td>N/A</td>";
          }
      }
      else
      {
          print "<td>N/A</td>";
      }
    }

    # Viper check
    if ($viper_on == "true")
    {
      if (isset($array['viper']))
      {
          if($array['viper'] == "true")
          {
              print "<td><a href='".$viper_api_url."/file/default/".$array['sha256']."' target='_blank'>Viper</a></td>";
          }
          else
          {
              print "<td>N/A</td>";
          }
      }
      else
      {
          print "<td>N/A</td>";
      }
    }
	
	# MISP check
    if ($misp_on == "true")
    {
      if (isset($array['misp']))
      {
          if($array['misp'] == "true")
          {
            print("<td>");
            foreach(explode(",", $array["misp_event"]) as $MEVENT) {
             
              $mispdata = $array["misp_data"];
              $minfo = $mispdata["info"];
              
              $datastring = "$minfo";
              
              print "<a href='$misp_url/events/view/$MEVENT' data-toggle='tooltip' data-placement='top' title='$datastring'>$MEVENT</a>";
            }
          }
          else
          {
              print "<td>N/A</td>";
          }
      }
      else
      {
          print "<td>N/A</td>";
      }
    }

    echo("<td>");
    if (array_key_exists("user-tags", $array)) {
      foreach($array["user-tags"] as $tag) {
        $id = $array["id"];
        $func = uniqid("mega_hack");
        print("<script>");
        print("function $func() {");
        print("  removeTag('$id', '$tag')");
        print("}</script>");
        print("<div class='input-group'>$tag <button type='button' class='btn btn-xs' 
                      onclick='".$func."()'>
                  <i class='glyphicon glyphicon-minus'></i>
              </button></div>
              ");
      }
    }
    print("<button class='btn btn-xs' type='button' onclick='addTag(".$array["id"].")'><i class='glyphicon glyphicon-plus'></i></button>");
    
    echo "</td>";

    #AV Logic
    print "<td>".$array['first_seen']."</td>";
	print "<td>".$array['timestamp']."</td>";
    if($array['positives'] == 0)
    {
        print "<td data-id='" . $array['positives'] . "'><button type='button' class='btn btn-danger btn-xs'>".$array['positives']."/".$array['total']."</button></td>";
    }
    else
    {
        print "<td data-id='" . $array['positives'] . "'><button type='button' class='btn btn-warning btn-xs' data-toggle='tooltip' data-placement='top' title='AV Results' onclick=\"launch_av_modal(".number_format($array['id'],0,'.','').",'AV Summary')\">".$array['positives']."/".$array['total']."</button></td>";
    }
    if($av_multiple == "true")
    {
        $found_vendor = false;
        foreach ($av_vendors as $vendor){
            if ($array['scans'][$vendor]!=""){
                $found_vendor = true;
                $res = $array["scans"][$vendor];
                print "<td>" . $vendor . "<br>" . $res . "</td>";
                break 1;
            }
        }
        if ($found_vendor == false){
            print "<td>[None found]</td>";
        }
    }
    else{
        print "<td>".$array['scans'][$av_vendor]."</td>";
    }
    print "<td>".$array['size']."</td>";
    print "<td>".$array['type']."</td>";
    print "<td>";
    if (isset($_GET["archive"])) {

    print "<button type='button' class='btn btn-primary btn-xs' data-toggle='tooltip' data-placement='top' title='UnArchive' onclick='UnarchFunc(".number_format($array['id'],0,'.','').")'><span class='glyphicon glyphicon-floppy-remove' aria-hidden='true'></span></button>";
    } else {
      print "<button type='button' class='btn btn-success btn-xs' data-toggle='tooltip' data-placement='top' title='Archive' onclick='archFunc(".number_format($array['id'],0,'.','').")'><span class='glyphicon glyphicon-floppy-saved' aria-hidden='true'></span></button>";
   }
    print "<button type='button' class='btn btn-danger btn-xs' data-toggle='tooltip' data-placement='top' title='Delete' onclick='delFunc(".number_format($array['id'],0,'.','').")'><span class='glyphicon glyphicon-remove' aria-hidden='true'></span></button>";
    print"</td>";

    print "</tr>";
    $int++;
}
?>
    </tbody>
    </table>
      <!-- page end-->

    <!-- Dynamic Modal content-->
    <div id="scrap_mod" class="modal fade" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-header modal-primary"><h4 class="modal-title" id="modal-title"></h4></div>
              <div class="modal-body" id="modal-bod"></div>
              <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal" onclick="reloadPage()">Refresh</button>
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
              </div>
            </div>
        </div>
    </div>
    <div id="load_mod" class="modal fade" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-body" id="load-bod"></div>
            </div>
        </div>
    </div>
    <!-- Dynamic Modal content-->
<footer>
<p><center>&copy; Super Magic System 2016</center></p>
</footer>
</div> <!-- /container -->
</body>


</html>
