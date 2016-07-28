<?php
require('VT/config.php');


function chopString($str, $maxlen) {
  return (strlen($str) > $maxlen)? substr($str,0,$maxlen)."...":$str;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>VT Hunter</title>
    <link rel="stylesheet" 
         href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css"
         integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" 
         crossorigin="anonymous"
    >
    
    <script src="js/jquery.js"></script>
    <script src="js/jquery-migrate.js"></script>
    <link rel="stylesheet" 
          href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.11.0/bootstrap-table.min.css"
    >
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" 
         integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ=="
         crossorigin="anonymous"></script>
    <script 
        src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.js">
    </script>
    <link rel="stylesheet" href="css/house_style.css">
    <link rel="stylesheet" href="css/spectrum.css">
    <script src="js/spectrum.js"></script>
    
    <!-- LOTS AND LOTS OF JS-->
    <script src="js/vt_ui.js"></script>
    <script src="js/vt_events.js"></script>
    <script src="js/vt_table_ui.js"></script>
    <script src="js/vt_ui.js"></script>
    <script src="js/vt_api_calls.js"></script>
    <script src="js/vt_sorters.js"></script>
    <script src="js/vt_tagging.js"></script>
    <script src="js/vt_virustotal.js"></script>

</head>


<script>
jQuery(document).ready(function($){
    $('[data-toggle="tooltip"]').tooltip();
});
</script>

<body>
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
<?php
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
    echo '<div class="alert alert-block alert-danger fade in">
          <button data-dismiss="alert" class="close close-sm" type="button">
          <i class="icon-remove"></i></button>Can\'t Connect to Mongo</div>';
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
<button class="btn btn-info" type="button">
      Alerts <span class="badge"><?php print $cursor->count();?></span>
</button>
</div>

<div class="btn-group">
  <button type="button" class="btn btn-primary dropdown-toggle" 
          data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          Download <span class="caret"></span>
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
	<button type='button' class='btn btn-success' data-toggle='tooltip' 
          data-placement='top' title='<?php 
echo $archStatus ?> Selected' 
          onclick="confirmArch('Archive','<?echo $archStatus ?>')">
          <?php 
echo $archStatus ?>
  </button>
</div>
	
<div class="btn-group">
  <button type="button" class="btn btn-warning dropdown-toggle" 
          data-toggle="dropdown" aria-haspopup="true" 
          aria-expanded="false">
          Settings  <span class="caret"></span>
  </button>

  <ul class="dropdown-menu">
    <li onclick="showlog('Log')"><a data-toggle='tooltip' 
        data-placement='top' title='Show Log'>Log</a>
    </li>
    <li onclick="showConfig('Config')"><a data-toggle='tooltip' 
        data-placement='top' title='Show Config'>Config</a>
    </li>
    <?php if($manual_pull == "true")
    {
        print "<li onclick=\"reloadData('VT Sync')\"><a data-toggle='tooltip' 
              data-placement='top' title='Get Alerts from VT'>Pull VT</a></li>";
		    print "<li role='separator' class='divider'></li>";
        if($crits_on == "true")
        {
            print "<li onclick=\"runCrits('Crits Lookup')\">
                    <a data-toggle='tooltip' data-placement='top' 
                       title='Crits Lookup'>Pull Crits</a></li>";
        }
		if($misp_on == "true")
        {
            print "<li onclick=\"runMISP('MISP Lookup')\">
                    <a data-toggle='tooltip' data-placement='top' 
                      title='Crits Lookup'>Pull MISP</a></li>";
        }
		if($viper_on == "true")
        {
            print "<li onclick=\"runViper('Viper Lookup')\">
                    <a data-toggle='tooltip' data-placement='top' 
                      title='Viper Lookup'>Pull Viper</a></li>";
        }
    }
    ?>
  </ul>
</div>

<div id="filter-bar"> </div>
<table id='mytable' data-toggle="table" 
       data-classes="table table-hover table-condensed" data-striped="true" 
       data-show-columns="true" data-search="true" data-pagination="true" 
      data-page-size="20">

  <thead>
  <tr>
    <th data-field="check" data-sortable="false">
      <input type="checkbox" onClick="toggle(this)"/> All<br/>
    </th>
    <th data-field="num" data-sortable="true" data-sorter="idSorter" 
        data-sort-name="_num_data">Details
    </th>
    <th data-field="rule" data-sortable="true">Rule</th>
    <th data-field="md5" data-sortable="true">MD5</th>
    <th data-field="filename" data-sortable="true">FileName</th>
    <?php 
    if($crits_on == "true") {
      print "<th data-field='crits' data-sortable='true'>CRITS</th>";
    }
    
    if($misp_on == "true") {
      print "<th data-field='crits' data-sortable='true'>MISP</th>";
    }

    if($viper_on == "true") {
      print "<th data-field='crits' data-sortable='true'>Viper</th>";
    }
    ?>
  
  <th data-field="tag" data-sortable="true" data-sorter="tagsorter">Tags</th>
  <th data-field="alert" data-sortable="true">Alert Date</th>
  <th data-field="seen" data-sortable="true">First Seen</th>
  <th data-field="compile" data-sortable="true">Compile</th>
  <th data-field="av" data-sortable="true" data-sorter="idSorter" 
      data-sort-name="_av_data">AV
  </th>
  <?php if($av_multiple == "true")
  {
    print "<th data-field='av_vendor' data-sortable='true'>AV Description</th>";
  }
  else
  {
    print "<th data-field='av_vendor' data-sortable='true'>" . $av_vendor;
    print "</th>";
  }?>
  <th data-field="Type" data-sortable="true">File Info</th>
  <th data-field="id" data-sortable="false">Action</th>
</tr>
</thead>
<tbody>
<?php 
$eventID = 1;

foreach ($cursor as $event)
{
    if (isset($event['archive'])){
        if($event['archive'] == true){
          print "<tr class='success' id='tr";
          print number_format($event['id'],0,'.','')."'>";}
        else {
          print "<tr id='tr".number_format($event['id'],0,'.','')."'>";
        }
    }
    else
    {
        print "<tr id='tr".number_format($event['id'],0,'.','')."'>";
    }
    print "<td><input type='checkbox' name='selected' id='".$event['md5'];
    print "' value='".number_format($event['id'],0,'.','')."'/></td>";
    print "<td data-id='".$eventID."'>
          <button type='button' 
                  class='btn btn-info btn-xs' data-toggle='tooltip' 
                  data-placement='top' title='Sample Details' 
                  onclick=\"launch_info_modal(";
    print number_format($event['id'],0,'.','').",'Details')\">
          #".$eventID."</button>";
    
    if ($event["ruleset_name"] != "Manual Import")
      print "<button type='button' class='btn btn-warning btn-xs' 
              data-toggle='tooltip' data-placement='top' title='Yara Results' 
              onclick=\"launch_yara_modal(";
      print number_format($event['id'],0,'.','').",'Yara')\">";
      print $event['ruleset_name']."</button></td>";
    print "<td>".$event['subject']."</td>";
    print "<td id='md5'><a href='https://www.virustotal.com/intelligence/search/
            ?query=".$event['sha256']."' target='_blank'>".$event['md5']."</a>";
    if(!empty($event['url'])){
        print "<span class='label label-default'>ITW</span>";
    }
    if(!empty($event['behaviour_dns'])){
        print "<span class='label label-default'>C2</span>";
    }
    print "</td>";
	  print "<td>";
    print "<div class='filenames'>";
    $submission = $event["submission_names"];


    print(chopString($submission[0], 20));

    if (count($submission) > 1) {
      $modifier = 0;
      if (strpos($submission[0], "_")) $modifier = 1;
      $padding = min(23, strlen($submission[0]));
      for ($i = 0; $i < 30-$padding; $i++) echo "&nbsp";
	    print("<button type='button' class='btn btn-xs btn-info' 
                      data-toggle='collapse' 
                      data-target='#names-{$event['id']}'>
                <i class='glyphicon glyphicon-menu-down'></i>
              </button>");

    print("<div  class='collapse' id='names-{$event['id']}'>");
    foreach (array_slice($event['submission_names'], 1) as $filename)
	  {
	    print chopString($filename,30) . "<br>";
	  }
  }
  print("</div>");
  print("</div>");
	print "</td>";
    # Crits check
    if ($crits_on == "true")
    {
      if (isset($event['crits']))
      {
          if($event['crits'] == "true")
          {
              print "<td><a href='".$crits_url."/samples/details/".$event['md5'];
              print " target='_blank'>Crits</a></td>";
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
      if (isset($event['viper']))
      {
          if($event['viper'] == "true")
          {
              print "<td><a href='".$viper_api_url."/file/default/".
                          $event['sha256']."' target='_blank'>Viper</a></td>";
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
      if (isset($event['misp']))
      {
          if($event['misp'] == "true")
          {
            print("<td>");
            foreach(explode(",", $event["misp_event"]) as $MEVENT) {
             
              $mispdata = $event["misp_data"];
              $minfo = $mispdata["info"];
              
              $datastring = "$minfo";
              
              print "<a href='$misp_url/events/view/$MEVENT' 
                        data-toggle='tooltip' data-placement='top' 
                        title='$datastring'>$MEVENT
                    </a>";
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
    if (array_key_exists("user-tags", $event)) {
      foreach($event["user-tags"] as $tag) {
        $id = $event["id"];
        $func = uniqid("mega_hack");
        print("<script>");
        print("function $func() {");
        print("  removeTag('$id', '{$tag["name"]}')");
        print("}</script>");
        print("<div class='input-group'><button class='btn' 
                    style='display: inline-block; padding: 2px 2px 2px 2px; 
                           font-size: 125%; color: white; 
                           background-color: {$tag["colour"]};' 
                    onclick=\"searchTag('{$tag["name"]}')\">{$tag["name"]}
                    </button> <button type='button' class='btn btn-xs' 
                      onclick='".$func."()'>
                  <i class='glyphicon glyphicon-minus'></i>
              </button></div>
              ");
      }
    }
    print("<button class='btn btn-xs' type='button' 
              onclick='addTag(".$event["id"].")'>
              <i class='glyphicon glyphicon-plus'></i></button>");
    
    echo "</td>";

    #AV Logic
    print "<td>".$event['first_seen']."</td>";
	  print "<td>{$event["date"]}</td>";
    print "<td>".$event['timestamp']."</td>";
    if($event['positives'] == 0)
    {
        print "<td data-id='" . $event['positives'] . "'><button type='button' class='btn btn-danger btn-xs'>".$event['positives']."/".$event['total']."</button></td>";
    }
    else
    {
        print "<td data-id='" . $event['positives'] . "'><button type='button' class='btn btn-warning btn-xs' data-toggle='tooltip' data-placement='top' title='AV Results' onclick=\"launch_av_modal(".number_format($event['id'],0,'.','').",'AV Summary')\">".$event['positives']."/".$event['total']."</button></td>";
    }
    if($av_multiple == "true")
    {
      $things_we_care_about = array();
      $found_vendor = false;
      foreach ($av_vendor as $vendor){
          if ($event['scans'][$vendor]!=""){
              $found_vendor = true;
              $scan = $vendor . ": ".$event["scans"][$vendor];
              $scan = (strlen($scan) > 40)?substr($scan,0,40)."...":$scan;
              array_push($things_we_care_about, $scan);
            }
        }
      
        print "<td class='filenames'>";
        if ($found_vendor) {
            if (count($things_we_care_about) == 1) {
              print($things_we_care_about[0]);
            } else {
              print($things_we_care_about[0]);
              $offset = min(43, -2+strlen($things_we_care_about[0]));
              for ($i = 0; $i < 45-$offset; $i++) print("&nbsp");
              print("<button class='btn btn-xs btn-info' data-toggle='collapse' data-target='#avs_{$event['id']}' type='button'>");
              print("<i class='glyphicon glyphicon-menu-down'></i>");
              print("</button><div class='collapse' id='avs_{$event['id']}'>");
              foreach (array_slice($things_we_care_about, 1) as $av) {
                print("$av<br>");
              }
              print("</div>");
            }
        } else {
            print "[None found]";
        }
        print "</td>";
    }
    else{
        print "<td>".$event['scans'][$av_vendor]."</td>";
    }
      
    print "<td>Type: ".$event['type']."<br>";
    print "Size: ".$event['size'];
    print "</td><td>";
    if (isset($_GET["archive"])) {

    print "<button type='button' class='btn btn-primary btn-xs' data-toggle='tooltip' data-placement='top' title='UnArchive' onclick='UnarchFunc(".number_format($event['id'],0,'.','').")'><span class='glyphicon glyphicon-floppy-remove' aria-hidden='true'></span></button>";
    } else {
      print "<button type='button' class='btn btn-success btn-xs' data-toggle='tooltip' data-placement='top' title='Archive' onclick='archFunc(".number_format($event['id'],0,'.','').")'><span class='glyphicon glyphicon-floppy-saved' aria-hidden='true'></span></button>";
   }
    print "<button type='button' class='btn btn-danger btn-xs' data-toggle='tooltip' data-placement='top' title='Delete' onclick='delFunc(".number_format($event['id'],0,'.','').")'><span class='glyphicon glyphicon-remove' aria-hidden='true'></span></button>";
    print"</td>";

    print "</tr>";
    $eventID++;
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

<script>
function showConfig(title) {
    response = "<?php
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
</script>

</html>
