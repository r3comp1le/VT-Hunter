<?
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
    catch ( MongoConnectionException $e )
    {
        echo "Can't Connect to Crits";
    }
}
if($source == 'mongo')
{
    try
    {
        $m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
        $db = $m->selectDB($mongo_db);
        $collection = new MongoCollection($db, $mongo_collection);
        echo "Mongo Connected";
    }
    catch ( MongoConnectionException $e )
    {
        echo "Can't Connect to Mongo";
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
    catch ( MongoConnectionException $e )
    {
        echo "Can't Connect to VT";
    }
}


?>