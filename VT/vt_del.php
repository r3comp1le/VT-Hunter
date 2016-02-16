<?
require('config.php');

$theId = intval($_POST['delId']);

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$id_check = array('id' => $theId);
$cursor = $collection->find($id_check);
foreach ($cursor as $array)
{
    $mongoID = $array['_id'];
    $collection->remove(array('_id' => new MongoId($mongoID)), array("justOne" => true));
    echo "200";
}

?>