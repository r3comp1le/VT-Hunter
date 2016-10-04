<?php
require('config.php');

$theId = intval($_POST['archId']);

$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);

$retval = $collection->findAndModify(
     array("id" => $theId),
     array('$set' => array('archive' => "true"))
);

$id_check = array('id' => $theId);
$cursor = $collection->find($id_check);
foreach ($cursor as $array)
{
    if($array['archive'] == "true")
    {
        echo "archived";
    }
    else
    {
        echo "fail";
    }
}

?>
