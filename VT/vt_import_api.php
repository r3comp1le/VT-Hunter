<?php

function importHash($MD5, $tags) {
  require('config.php');
  $date = date("F j, Y, g:i a");
  
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
  $taco = new MongoCollection($db,  $mongo_collection_tags);
  $int_del = 0;
  $int_add = 0;
  if ($thejson["response_code"] == 1) {
    try {
      $int_add = add_event($thejson, $collection, $stats, $taco, $tags);
    } catch (MongoConnectionException $e) {
      return 1;
    }
  }
  return 0;
}
?>
