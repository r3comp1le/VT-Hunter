<?
require('VT/config.php');
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VT Hunter</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" crossorigin="anonymous">
    <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.css">
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
}
</style>

<script>
function toggle(source) {
checkboxes = document.getElementsByName('selected');
for(var i=0, n=checkboxes.length;i<n;i++) {
    checkboxes[i].checked = source.checked;
}
}

function getModal() {
$.post( "vt_getcontent.php", { "theId": theId },function( data )
{
    console.log(data);
});
}

function launch_info_modal(id){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

        yara = data.match;
        yara0 = yara.replace(/\n/g, "<br>");
        yara1 = yara0.replace(/\*begin_highlight*/g, "<mark>");
        yara2 = yara1.replace(/\*end_highlight*/g, "</mark>");
        
        $(".modal-body").html(
            "<b>MD5</b>: " + data.md5 + "<br>" + 
            "<b>SHA1</b>: " + data.sha1 + "<br>" + 
            "<b>SHA256</b>: " + data.sha256 + "<br>" +
            "<b>First Seen</b>: " + data.first_seen + "<br>" +
            "<b>Last Seen</b>: " + data.last_seen + "<br>" +
            "<b>Size</b>: " + data.size + "<br>" +
            "<b>File Type</b>: " + data.type + "<br>"
            )
        $("#modal-yara").html(
            "<b>Date</b>: " + data.date + "<br>" + 
             yara2 
            )

        $('#info_place').modal('show');
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

function downloadFunc() {
    var md5s = []
    $("input:checkbox[name=selected]:checked").each(function(){
        md5 = this.id;
        md5s.push(md5);
        console.log(md5);
    });
    
    /*$.post( "vtdown.php", { "md5s[]": md5s },function( data )
    {
        console.log(data);
    });
    */
}

function confirmDel(title) {
    response = "Are you sure you want to Delete?  <button type='button' class='btn btn-danger' onclick=\"deleteFunc()\">YES</button>";
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
                console.log("Deleted");
            }
            else
            {
                console.log("Did not delete");
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

function showlog(title) {
    jQuery.get('VT/vt.log', function(data) {
        data_new = data.replace(/\n/g, "<br>end");
        var logz = data_new.split("end");
        start = (logz.length - 14);
        end = logz.length;
        var log = logz.slice(start, end)
        $("#modal-bod").html(log)
        $("#modal-title").html(title);
        $('#scrap_mod').modal('show');
    });
    
}
function reloadData(title) {
    $.ajax({
        type: "GET",
        url: "VT/vt_api_to_db.php",
        success: function(response){
            $("#modal-bod").html(response);
            $("#modal-title").html(title);
            $('#scrap_mod').modal('show');
        },
    });
}

function showConfig(title) {
    response = "<?
    print "Mongo DB: " . $mongo_db . "<br>";
    print "Mongo Collection: " . $mongo_collection . "<br>";

    #Crits Connections
    print "Crits Toggle: " . $crits_on . "<br>";
    print "Crits URL: " . $crits_url . "<br>";
    ?>";
    $("#modal-bod").html(response);
    $("#modal-title").html(title);
    $('#scrap_mod').modal('show');
}


</script>

<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <a class="navbar-brand" href="#">VT Hunter</a>
    </div>
  </div>
</nav>

<div class="container">
<br><br><br><br>
<?
try
{
    $m = new MongoClient();
    $db = $m->selectDB($mongo_db);
    $collection = new MongoCollection($db, $mongo_collection);
}
catch ( MongoConnectionException $e )
{
    echo '<div class="alert alert-block alert-danger fade in"><button data-dismiss="alert" class="close close-sm" type="button"><i class="icon-remove"></i></button>Can\'t Connect to Mongo</div>';
    exit();
}
$cursor = $collection->find();
?>

<button class="btn btn-info" type="button">Samples <span class="badge"><?print $cursor->count();?></span></button>
<button type='button' class='btn btn-primary' onclick="downloadFunc('Download')">Download</button>
<button type='button' class='btn btn-danger' onclick="confirmDel('Delete')">Delete</button>
<button type='button' class='btn btn-warning' onclick="reloadData('VT Sync')">ReLoad</button>
<button type='button' class='btn btn-warning' onclick="showlog('Log')">Log</button>
<button type='button' class='btn btn-warning' onclick="showConfig('Config')" align=right>Config</button>

<div id="filter-bar"> </div>
<table id='mytable' data-toggle="table" data-classes="table table-hover table-condensed" data-striped="true" data-show-columns="true" data-search="true" data-pagination="true" data-page-size="20">
<thead>
<tr>
  <th data-field="check" data-sortable="false"><input type="checkbox" onClick="toggle(this)"/> All<br/></th>
  <th data-field="num" data-sortable="false">Details</th>
  <th data-field="set" data-sortable="true">Rule Set</th>
  <th data-field="rule" data-sortable="true">Rule</th>
  <th data-field="md5" data-sortable="true">MD5</th>
  <th data-field="crits" data-sortable="true">CRITS</th>
  <th data-field="seen" data-sortable="true">First Seen</th>
  <th data-field="av" data-sortable="true">AV</th>
  <th data-field="McAfee" data-sortable="true">McAfee</th>
  <th data-field="size" data-sortable="true">Size</th>
  <th data-field="Type" data-sortable="true">Type</th>
  <th data-field="id" data-sortable="false">Delete</th>
</tr>
</thead>
<tbody>
<?
$int = 1;

foreach ($cursor as $array)
{
    print "<tr id='tr".number_format($array['id'],0,'.','')."'>";
    print "<td><input type='checkbox' name='selected' id='".$array['md5']."' value='".number_format($array['id'],0,'.','')."'/></td>";
    print "<td><button type='button' class='btn btn-info btn-xs' onclick='launch_info_modal(".number_format($array['id'],0,'.','').")'>".$int."</button></td>"; 
    print "<td>".$array['ruleset_name']."</td>"; 
    print "<td>".$array['subject']."</td>"; 
    print "<td id='md5'><a href='https://www.virustotal.com/intelligence/search/?query=".$array['sha256']."' target='_blank'>".$array['md5']."</a></td>"; 
    
    # Crits check
    if($crits_on == "true")
    {
        $url = $crits_url . "/api/v1/samples/?c-md5=".$array['md5']."&username=".$crits_user."&api_key=".$crits_api_key."&regex=1";
        $result2 = file_get_contents($url, false);
        $thejson = json_decode($result2, true);
        if($thejson['meta']['total_count'] == 1)
        {
            print "<td><a href='".$crits_url."/samples/details/".$array['md5']."' target='_blank'>Crits</a></td>"; 
        }
        print "<td>Error</td>";
    }
    else
    {
        print "<td>OFF</td>";
    }
    
    #AV Logic
    print "<td>".$array['first_seen']."</td>"; 
    if($array['positives'] == 0)
    {
        print "<td><button type='button' class='btn btn-danger btn-xs'>".$array['positives']."/".$array['total']."</button>";    
    }
    else
    {
        print "<td><button type='button' class='btn btn-warning btn-xs' onclick=\"launch_av_modal(".number_format($array['id'],0,'.','').",'AV Summary')\">".$array['positives']."/".$array['total']."</button></td>";  
    }            

    print "<td>".$array['scans']['McAfee']."</td>";
    print "<td>".$array['size']."</td>";
    print "<td>".$array['type']."</td>";
    print "<td><button type='button' class='btn btn-danger btn-xs' onclick='delFunc(".number_format($array['id'],0,'.','').")'><span class='glyphicon glyphicon-remove' aria-hidden='true'></span></button></td>";
    print "</tr>";
    $int++;
}
?>
    </tbody>
    </table> 
      <!-- page end-->

    <!-- Modal content-->
    <div id="info_place" class="modal fade" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-header modal-primary"><h4 class="modal-title">Info</h4></div>
              <div class="modal-body"></div>
              <div class="modal-header modal-primary"><h4 class="modal-title">Yara Match</h4></div>
              <div class="modal-body" id="modal-yara"></div>
              <div class="modal-footer">
                <button type="button" class="btn btn-danger" data-dismiss="modal">Close</button>
              </div>
            </div>
        </div>
    </div>
    <!-- Modal content-->
    <!-- Dynamic Modal content-->
    <div id="scrap_mod" class="modal fade" role="dialog">
        <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-header modal-primary"><h4 class="modal-title" id="modal-title"></h4></div>
              <div class="modal-body" id="modal-bod"></div>
              <div class="modal-footer">
                <button type="button" class="btn btn-primary" data-dismiss="modal">Close</button>
              </div>
            </div>
        </div>
    </div>
    <!-- Dynamic Modal content-->
<footer>
<p>&copy; r3comp1le 2015</p>
</footer>
</div> <!-- /container -->

<script src="http://code.jquery.com/jquery-1.11.3.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==" crossorigin="anonymous"></script>
<script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.js"></script>
</body>
</html>