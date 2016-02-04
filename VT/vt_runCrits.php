<?
require('config.php');

$counter = 0;
$m = new MongoClient();
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$cursor = $collection->find();


if($crits_on == "true")
{
    foreach ($cursor as $array)
    {   
        $url = $crits_url . "/api/v1/samples/?c-md5=".$array['md5']."&username=".$crits_user."&api_key=".$crits_api_key."&regex=1";
        $result2 = file_get_contents($url, false);
        $thejson = json_decode($result2, true);
        if($thejson['meta']['total_count'] == 1)
        {
            $retval = $collection->findAndModify(
                 array("id" => $array['id']),
                 array('$set' => array('crits' => "true"))
            );
            $counter++;
        }
    }
    echo "Found " . $counter . " Samples in Crits";
}
else
{
    echo "Crits config is set to False";
}
?>
