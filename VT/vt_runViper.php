<?php
require('config.php');

$counter = 0;
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$cursor = $collection->find();


if($viper_on == "true")
{
    foreach ($cursor as $array)
    {   
        $url = $viper_url . "/file/find";
		$data = "md5=" . $array['md5'];
		$opts = array(
            'http' => array(
                'method'  => 'POST',
                #'proxy' => 'tcp://proxy.com:5555',
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'content' => $data,
                )
        );
        $context  = stream_context_create($opts);
        $result2 = file_get_contents($url, false, $context);
        $thejson = json_decode($result2, true);
		$res = count($thejson['default']);
        if($res > 0)
        {
            $retval = $collection->findAndModify(
                 array("id" => $array['id']),
                 array('$set' => array('viper' => "true"))
            );
            $counter++;
        }
    }
    echo "Found " . $counter . " Samples in Viper";
}
else
{
    echo "Viper config is set to False";
}
?>
