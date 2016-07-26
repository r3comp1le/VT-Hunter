<?php
require('config.php');
require('utils.php');

# Log file
$filesize = filesize("vt.import.log");

#Make sure we don't have a really big file
if($filesize < 1000){$log = fopen("vt.log", "a");}

#If we've gone over 1000 lines, clear the file
else{$log = fopen("vt.import.log", "w");}

#Get today's date
$date = date("F j, Y, g:i a");

fwrite($log, "<b>".$date."</b><br>\n");


foreach ($_POST["md5s"] as $MD5) { 
  # Get the alert feed
  $url_vt_mal = "https://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=$vt_mal_key&resource=$MD5";

  $opts = array(
      'http' => array(
          'method'  => 'GET',
          'request_fulluri' => true,
          )
  );

  $context  = stream_context_create($opts);
  $result = file_get_contents($url_vt_mal, false, $context);
  $thejson = json_decode($result, true);

  # Mongo connection
  $m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
  $db = $m->selectDB($mongo_db);
  $collection = new MongoCollection($db, $mongo_collection);
  $stats = new MongoCollection($db, $mongo_collection_stats);
  $int_del = 0;
  $int_add = 0;

  if ($thejson["response_code"] == 1) {
    try {
      $int_add = add_event($thejson, $collection, $stats);
    } catch (MongoConnectionException $e) {
      echo "Mongo is kill $e";
      die();
    }
  }

echo "Imported!";
}
echo "Samples Added: <span class='label label-primary'>" . $int_add . "</span><br>";
echo "VT Alerts Deleted: <span class='label label-danger'>"  . $int_del . "</span><br>";

?>
