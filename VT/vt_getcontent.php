<?php
require('config.php');

$theId = intval($_POST['theId']);

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$id_check = array('id' => $theId);
$cursor = $collection->find($id_check);

header('Content-Type: application/json');
foreach($cursor as $array)
{
echo json_encode($array);
}

?>
