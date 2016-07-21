<?

require("config.php");
# Mongo connection
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, "tags");

if (!$collection) {
  echo json_encode(array());
}

$cursor = $collection->find();

$retval = array();
foreach ($cursor as $tag) {
  array_push($retval, $tag);
}
echo json_encode($retval);
?>
