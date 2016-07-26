<?php
require('config.php');

$source = $_POST['source'];


if($source == 'crits')
{
    try
    {
        $url = $crits_url . "/api/v1/samples/?username=".$crits_user."&api_key=".$crits_api_key."&limit=1";
        $opts = array(
            'http' => array(
                'method'  => 'GET',
                #'proxy' => 'tcp://proxy.com:5555',
                'request_fulluri' => true,
                )
        );
        $context  = stream_context_create($opts);
        $result = file_get_contents($url, false, $context);
        $thejson = json_decode($result, true);
        $res = count($thejson);
        if($res > 0){echo "Crits Connected";}else{echo "Can't Connect to Crits";}
    }
    catch ( Exception $e )
    {
        echo $e->getMessage();
    }
}
if($source == 'misp')
{
    try
    {
        $data = array('request' => array('value' => $array['md5']));
        $data_json = json_encode($data);
        $context = stream_context_create(array(
            'http' => array(
                'method' => 'GET',
                'header' => "Authorization: " . $misp_api_key . "\r\n" .
                            "Accept: application/json\r\n" .
                            "content-type: application/json\r\n"
            )
        ));
        $url = $misp_url . "/servers/getVersion";
        $result2 = file_get_contents($url, false, $context);
        $thejson = json_decode($result2, true);
        $res = count($thejson);
        if($res > 0){echo "MISP Connected";}else{echo "Can't Connect to MISP";}
    }
    catch ( Exception $e )
    {
        echo $e->getMessage();
    }
}
if($source == 'mongo')
{
    try
    {
        $m = new MongoDB\Client("mongodb://".$mongo_server_host.":".$mongo_server_port);
        $db = $m->selectDB($mongo_db);
        $collection = new MongoCollection($db, $mongo_collection);
        echo "Mongo Connected";
    }
    catch ( MongoConnectionException $e )
    {
        echo $e->getMessage();
    }
}
if($source == 'vt')
{
   try
    {
        $url_vt_mal = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=".$vt_mal_key;
        $opts = array(
            'http' => array(
                'method'  => 'GET',
                #'proxy' => 'tcp://proxy.com:5555',
                'request_fulluri' => true,
                )
        );
        $context  = stream_context_create($opts);
        $result = file_get_contents($url_vt_mal, false, $context);
        $thejson = json_decode($result, true);
        $res = count($thejson);
        if($res > 0){echo "VT Connected";}else{echo "Can't Connect to VT";}
    }
    catch ( Exception $e )
    {
        echo $e->getMessage();
    }
}

if($source == 'viper')
{
   try
    {
        $url_viper = $viper_api_url . "/test";
        $opts = array(
            'http' => array(
                'method'  => 'GET',
                #'proxy' => 'tcp://proxy.com:5555',
                )
        );
        $context  = stream_context_create($opts);
        $result = file_get_contents($url_viper, false, $context);
        $thejson = json_decode($result, true);
        if($thejson['message'] == "test"){echo "Viper Connected";}else{echo "Can't Connect to Viper";}
    }
    catch ( Exception $e )
    {
        echo $e->getMessage();
    }
}



?>
