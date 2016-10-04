<?php
require("config.php");

# Mongo connection
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, "tags");

$colour = $_POST["colour"];
$name = $_POST["name"];

$result = $collection->insert(array("name"=>$name, "colour"=>$colour));

if (!$result) {
  echo "An error occured :(";
} else {
  echo "Added sucessfully";
}
?>
