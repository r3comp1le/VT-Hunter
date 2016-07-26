<?php
require('config.php');

$counter = 0;
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$cursor = $collection->find();


if($misp_on == "true")
{
    foreach ($cursor as $array)
    {
        $data = array('request' => array('value' => $array['md5'],"type" => "md5"));
        $data_json = json_encode($data);
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'POST',
                'header' => "Authorization: " . $misp_api_key ."\r\n" .
                            "Accept: application/json\r\n" .
                            "content-type: application/json\r\n",
                'content' => $data_json
            )
        ));
        $url = $misp_url . "/events/restSearch/download";
        $result2 = file_get_contents($url, true, $context);
        if ($result2 != false){
            $thejson = json_decode($result2, true);
            if (is_array($thejson) && array_key_exists('response',$thejson)){
                $jsoncount = count($thejson['response']);
                if($jsoncount > 0)
                {
                    $jsonevents = "";
                    $jsoncounter = 0;
                    foreach ($thejson['response'] as $jsonevent)
                    {
                        $jsoncounter++;
                        if($jsoncount==0 || $jsoncount == $jsoncounter)
                        {
                            $jsonevents .= $jsonevent['Event']['id'];
                        }
                        else
                        {
                            $jsonevents .= $jsonevent['Event']['id'] .', ';
                        }
                    }
                    $retval = $collection->findAndModify(
                         array("id" => $array['id']),
                         array('$set' => array('misp' => "true",'misp_event' => $jsonevents,
                                               "misp_data"=>$jsonevent["Event"]))
                    );
                    $counter++;
                }
            }
        }
    }
    echo "Found " . $counter . " Samples in MISP";
}
else
{
    echo "MISP config is set to False";
}
?>
