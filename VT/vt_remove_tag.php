<?

require("config.php");

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);

$cursor = $collection->findOne(array("id" => intval($_POST["id"])));
print("Removing ".$_POST["tag"]);

function getIndex($const, $arr) {
  for ($i = 0; $i < count($arr)+1; $i++) {
    if (isset($arr[$i]) && $arr[$i] == $const) return $i;
  }
  return -1;
}

print_r($cursor["user-tags"]);
if (in_array($_POST["tag"], $cursor["user-tags"])) {
  print("Found...");
  
  $ind = getIndex($_POST["tag"], $cursor["user-tags"]);
  unset($cursor["user-tags"][$ind]);
  $collection->update(array("id"=>intval($_POST["id"])),
                      $cursor);

}
?>
