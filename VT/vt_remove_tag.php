<?php

require("config.php");

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);

$cursor = $collection->findOne(array("id" => intval($_POST["id"])));

function getIndex($const, $arr) {
  for ($i = 0; $i < count($arr)+1; $i++) {
    if (isset($arr[$i]) && $arr[$i]["name"] == $const) return $i;
  }
  return -1;
}

print_r($cursor["user-tags"]);
$ind = getIndex($_POST["tag"], $cursor["user-tags"]);
if ($ind != -1) {
  print("Found...");
  
  unset($cursor["user-tags"][$ind]);
  $collection->update(array("id"=>intval($_POST["id"])),
                      $cursor);

}
?>
