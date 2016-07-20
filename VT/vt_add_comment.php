<?
require("config.php");

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$stats = new MongoCollection($db, $mongo_collection_stats);

$new_comment = $_POST["comment"];
$id = $_POST["id"];

echo "Adding $new_comment to event ID $id";

$res = $collection->update(
                array("id"=>intval($id)),
                array('$set' => array("comment"=>$new_comment)),
                array("upsert" => false)
              );
print_r($res);
?>
