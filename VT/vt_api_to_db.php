<?
require('config.php');

#API KEY
$api_key = $vt_key;

#log file
$log = fopen("vt.log", "a");
$date = date("F j, Y, g:i a");
fwrite($log, "<b>".$date."</b>\n");

$url = "https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=".$api_key;
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

$m = new MongoClient();
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$int_del = 0;
$int_add = 0;

# Look through JSON feed
foreach ($thejson['notifications'] as $array)
{
    $vt_date = $array['date']; 
    $vt_first_seen = $array['first_seen']; 
    $vt_id = $array['id']; 
    $vt_last_seen = $array['last_seen']; 
    $vt_match = $array['match']; 
    $vt_md5 = $array['md5']; 
    $vt_positives = $array['positives']; 
    $vt_ruleset_name = $array['ruleset_name']; 
    $vt_scans = $array['scans']; 
    $vt_sha1 = $array['sha1']; 
    $vt_sha256 = $array['sha256']; 
    $vt_size = $array['size']; 
    $vt_subject = $array['subject']; 
    $vt_total = $array['total']; 
    $vt_type = $array['type']; 

    # Check if ID exist in DB
    $id_check = array('id' => $vt_id);
    $cursor = $collection->find($id_check);

    # If VT ID already exist, delete from VTI
    if($cursor->count() > 0)
    {
        $del_url = "https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key=".$api_key;
        $opts2 = array(
            'http' => array(
            'method'  => 'POST',
            #'proxy' => 'tcp://proxy.com:55555',
            'header' => "Content-Type: application/json",
            'content' => "[".$vt_id."]",
            'request_fulluri' => true,
            )
        );
        $context2  = stream_context_create($opts2);
        $result2 = file_get_contents($del_url, false, $context2);
        $thejson = json_decode($result2, true);
        if($thejson['deleted'] == 1){$int_del++;}
        else{fwrite($log, "ERROR!!!  Could not delete: " . $vt_id . "\n");}
    }
    
    # Add to mongodb
    else
    {
        $sample_info = array(
            "date" => $vt_date,
            "first_seen" => $vt_first_seen, 
            "id" => $vt_id,
            "last_seen" => $vt_last_seen, 
            "match" => $vt_match,
            "md5" => $vt_md5, 
            "positives" => $vt_positives,
            "ruleset_name" => $vt_ruleset_name, 
            "scans" => $vt_scans,
            "sha1" => $vt_sha1, 
            "sha256" => $vt_sha256,
            "size" => $vt_size,
            "subject" => $vt_subject,
            "total" => $vt_total, 
            "type" => $vt_type
            );
        $collection->insert($sample_info);
        $int_add++;
        
        $del_url = "https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key=".$api_key;
        $opts3 = array(
            'http' => array(
            'method'  => 'POST',
            #'proxy' => 'tcp://proxy.com:55555',
            'header' => "Content-Type: application/json",
            'content' => "[".$vt_id."]",
            'request_fulluri' => true,
            )
        );
        $context3  = stream_context_create($opts3);
        $result3 = file_get_contents($del_url, false, $context3);
        $thejson = json_decode($result3, true);
        if($thejson['deleted'] == 1){$int_del++;}
        else{fwrite($log, "ERROR!!!  Could not delete: " . $vt_id . "\n");}
    }
}
echo "Samples Added: <span class='label label-primary'>" . $int_del . "</span><br>";
echo "VT Alerts Deleted: <span class='label label-danger'>"  . $int_add . "</span><br>";

fwrite($log, "Samples Added: <span class='label label-primary'>" . $int_add . "</span>\n");
fwrite($log, "VT Alerts Deleted: <span class='label label-danger'>" . $int_del . "</span>\n\n");
fclose($log);

?>