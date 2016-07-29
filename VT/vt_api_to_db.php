<?php
require('config.php');
mb_internal_encoding("UTF-8");
#Get today's date
$date = date("F j, Y, g:i a");

# Get the alert feed
$url_vt_mal = "http://www.virustotal.com/intelligence/hunting/notifications-feed/?key=$vt_mal_key";
$opts = array(
    'http' => array(
        'method'  => 'GET',
        'request_fulluri' => true,
        ),
);

$context  = stream_context_create($opts);
$result = file_get_contents($url_vt_mal, false, $context);

if (!$result) {
  print("VirusTotal didn't respond :(");
  die();
}
$thejson = json_decode($result, true);

# Mongo connection
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, $mongo_collection);
$stats = new MongoCollection($db, $mongo_collection_stats);
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

    if ($cursor->count() == 0) {
      # Add to mongodb
      # Check if we've seen the hash before
      $hash_check = array('md5' => $vt_md5);
      $cursor = $collection->find($hash_check);
         
      if ($cursor->count() != 0) {
        $titles = $cursor->getNext()["submission_names"];
        #We've seen the hash before, update the count and all that
        $url_vt_search = "http://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=".$vt_search_key."&resource=".$vt_md5;
        $opts_vt_search = array(
          'http' => array(
            'method'  => 'GET',
            'request_fulluri' => true,
            )
          );
        $context_vt_search  = stream_context_create($opts_vt_search);
        $result_vt_search = file_get_contents($url_vt_search, false, $context_vt_search);        
        if (!$result_vt_search) {
          print("VT did a bad :(");
          break 1;
        } 
        
        $thejson_vt_search = json_decode($result_vt_search, true);
        $newtitles = $thejson_vt_search["submission_names"];
        $reallynewtitles = array(); 
        if (is_array($titles) && is_array($newtitles)) {
          $reallynewtitles = array_merge($titles, $thejson_vt_search["submission_names"]);
        } else if (is_array($titles)) {
          //$newtitles isn't actually an array
          array_push($titles, $newtitles);
          $reallynewtitles = $titles;

        } else if (is_array($newtitles)) {
          //$titles isn't an array
          array_push($newtitles, $titles);
          $reallynewtitles = $newtitles;
                  
        } else {
          //Neither of them are!?
          $reallynewtitles = array($newtitles, $titles);
        }
       
        if (count($reallynewtitles) == 0 || $reallynewtitles == "") $reallynewtitles = array("NONE FOUND!");
        $collection->update(
          array("md5" => $vt_md5),
          array("submission_names" => $reallynewtitles)
        );


      } else {
        #This is a totally new hash, add it normally
         
        # Add to stats
        $criteria = array('rule' => $vt_ruleset_name);
        $doc = $stats->findOne($criteria);
        if(empty($doc)){
              $stats->insert(array("count" => 1,"rule" => $vt_ruleset_name));}
        else{
              $stats->update(array('rule' => $vt_ruleset_name), array('$inc' => array('count' => 1)));
        }

        $sample_details = array();

        # Query VT for allinfo parameter
        if($vt_search == "true") {
            $url_vt_search = "http://www.virustotal.com/vtapi/v2/file/report?allinfo=1&apikey=".$vt_search_key."&resource=".$vt_md5;
            $opts_vt_search = array(
                'http' => array(
                    'method'  => 'GET',
                    #'proxy' => 'tcp://proxy.com:55555',
                    'request_fulluri' => false,
                  )
              );
              $context_vt_search  = stream_context_create($opts_vt_search);
              $result_vt_search = file_get_contents($url_vt_search, false, $context_vt_search);
              $thejson_vt_search = json_decode($result_vt_search, true);

              if (isset($thejson_vt_search['times_submitted'])) {
                $vt_times_submitted = $thejson_vt_search['times_submitted'];
              } else{
                $vt_times_submitted = "";
              }

              if (isset($thejson_vt_search['submission_names'])){
                $vt_submission_names = $thejson_vt_search['submission_names'];
              } else {
                $vt_submission_names = "";}

              if (isset($thejson_vt_search['additional_info']['trid'])){
                $vt_trid = $thejson_vt_search['additional_info']['trid'];
              } else {
                $vt_trid = "";}
              if (isset($thejson_vt_search['additional_info']['pe-debug'])){
                $vt_pe_debug = $thejson_vt_search['additional_info']['pe-debug'];
              } else {
                $vt_pe_debug = "";}
              if (isset($thejson_vt_search['additional_info']['pe-imphash'])){
                $vt_imphash = $thejson_vt_search['additional_info']['pe-imphash'];
              } else {
                $vt_imphash = "";}
              if (isset($thejson_vt_search['additional_info']['magic'])){
                $vt_magic = $thejson_vt_search['additional_info']['magic'];
              } else {
                $vt_magic = "";}

              if (isset($thejson_vt_search['additional_info']['pe-timestamp'])){
                $vt_timestamp = gmdate("Y-m-d\TH:i:s\Z",$thejson_vt_search['additional_info']['pe-timestamp']);
              } else {
                $vt_timestamp = "";}
              if (isset($thejson_vt_search['additional_info']['f-prot-unpacker'])){
                $vt_unpacker = $thejson_vt_search['additional_info']['f-prot-unpacker'];
              } else {
                $vt_unpacker = "";}
              if (isset($thejson_vt_search['authentihash'])){
                $vt_authentihash = $thejson_vt_search['authentihash'];
              } else {
                $vt_authentihash = "";}
              if (isset($thejson_vt_search['resource'])){
                $vt_resource = $thejson_vt_search['resource'];
              } else {
                $vt_resource = "";}
              if (isset($thejson_vt_search['ssdeep'])){
                $vt_ssdeep = $thejson_vt_search['ssdeep'];
              } else {
                $vt_ssdeep = "";}
              if (isset($thejson_vt_search['ITW_urls'])){
                $vt_ITW_urls = $thejson_vt_search['ITW_urls'];
              } else {
                $vt_ITW_urls = "";}
              if (isset($thejson_vt_search['tags'])){
                $vt_tags = $thejson_vt_search['tags'];
              } else {
                $vt_tags = "";}

              if (isset($thejson_vt_search['additional_info']['behaviour-v1']['network']['udp'])){
                $vt_behaviour_udp = $thejson_vt_search['additional_info']['behaviour-v1']['network']['udp'];
              } else {
                $vt_behaviour_udp = "";}
              if (isset($thejson_vt_search['additional_info']['behaviour-v1']['network']['http'])){
                $vt_behaviour_http = $thejson_vt_search['additional_info']['behaviour-v1']['network']['http'];
              } else {
                $vt_behaviour_http = "";}
              if (isset($thejson_vt_search['additional_info']['behaviour-v1']['network']['dns'])){
                $vt_behaviour_dns = $thejson_vt_search['additional_info']['behaviour-v1']['network']['dns'];
              } else {
              $vt_behaviour_dns = "";}
              if (isset($thejson_vt_search['additional_info']['behaviour-v1']['network']['tcp'])){
                $vt_behaviour_tcp = $thejson_vt_search['additional_info']['behaviour-v1']['network']['tcp'];
              } else {
                $vt_behaviour_tcp = "";}

              if (isset($thejson_vt_search['additional_info']['sigcheck']['publisher'])){
                $vt_sigcheck_pub = $thejson_vt_search['additional_info']['sigcheck']['publisher'];
              } else {
                $vt_sigcheck_pub = "";}
              if (isset($thejson_vt_search['additional_info']['sigcheck']['verified'])){
                $vt_sigcheck_verified = $thejson_vt_search['additional_info']['sigcheck']['verified'];
              } else {
                $vt_sigcheck_verified = "";}
              if (isset($thejson_vt_search['additional_info']['sigcheck']['link date'])){
                $vt_sigcheck_date = $thejson_vt_search['additional_info']['sigcheck']['link date'];
              } else {
                $vt_sigcheck_date = "";}
              if (isset($thejson_vt_search['additional_info']['sigcheck']['signers'])){
                $vt_sigcheck_signers = $thejson_vt_search['additional_info']['sigcheck']['signers'];
              } else {
                $vt_sigcheck_signers = "";}

              if (isset($thejson_vt_search['additional_info']['exiftool']['CompanyName'])){
                $vt_exif_company = $thejson_vt_search['additional_info']['exiftool']['CompanyName'];
              } else {
                $vt_exif_company = "";}
              if (isset($thejson_vt_search['additional_info']['exiftool']['LanguageCode'])){
                $vt_exif_LanguageCode = $thejson_vt_search['additional_info']['exiftool']['LanguageCode'];
              } else {
                $vt_exif_LanguageCode = "";}
              if (isset($thejson_vt_search['additional_info']['exiftool']['OriginalFileName'])){
                $vt_exif_OriginalFileName = $thejson_vt_search['additional_info']['exiftool']['OriginalFileName'];
              } else {
                $vt_exif_OriginalFileName = "";}
              if (isset($thejson_vt_search['additional_info']['exiftool']['TimeStamp'])){
                $vt_exif_TimeStamp = $thejson_vt_search['additional_info']['exiftool']['TimeStamp'];
              } else {
                $vt_exif_TimeStamp = "";}
              if (isset($thejson_vt_search['additional_info']['exiftool']['InternalName'])){
                $vt_exif_InternalName = $thejson_vt_search['additional_info']['exiftool']['InternalName'];
            } else {
              $vt_exif_InternalName= "";}
            if (isset($thejson_vt_search['additional_info']['exiftool']['ProductName'])){
              $vt_exif_ProductName = $thejson_vt_search['additional_info']['exiftool']['ProductName'];
            } else {
              $vt_exif_ProductName = "";}

            #search api vars
            $sample_search_info = array(
            "sample_info" => "true",
            "times_submitted" => $vt_times_submitted,
                "submission_names" => $vt_submission_names,
                "trid" => $vt_trid,
                "imphash" => $vt_imphash,
                "magic" => $vt_magic,
                "sigcheck_pub" => $vt_sigcheck_pub,
                "sigcheck_verified" => $vt_sigcheck_verified,
                "sigcheck_date" => $vt_sigcheck_date,
                "sigcheck_signers" => $vt_sigcheck_signers,
                "timestamp" => $vt_timestamp,
                "unpacker" => $vt_unpacker,
                "authentihash" => $vt_authentihash,
                "pe_debug" =>$vt_pe_debug,
                "resource" => $vt_resource,
                "ssdeep" => $vt_ssdeep,
                "behaviour_upd" => $vt_behaviour_udp,
                "behaviour_http" => $vt_behaviour_http,
                "behaviour_dns" => $vt_behaviour_dns,
                "behaviour_tcp" => $vt_behaviour_tcp,
                "ITW_urls" => $vt_ITW_urls,
                "exif_company" => $vt_exif_company,
                "exif_LanguageCode" => $vt_exif_LanguageCode,
                "exif_OriginalFileName" => $vt_exif_OriginalFileName,
                "exif_TimeStamp" => $vt_exif_TimeStamp,
                "exif_InternalName" => $vt_exif_InternalName,
                "exif_ProductName" => $vt_exif_ProductName,
                "tags" => $vt_tags,
                );
                $sample_details = array_merge($sample_details, $sample_search_info);
            }

          #vt alert vars
          $sample_alert_info = array(
              "alert_info" => "true",
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

        $sample_details = array_merge($sample_details, $sample_alert_info);
    
        if (isset($sample_details["id"]) && isset($sample_details["md5"])) {
          $collection->insert($sample_details);
          $int_add++;
        }
        if($delete_alerts == "true")
        {
            $del_url = "https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key=".$vt_mal_key;
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
        }

      }
  }
    
}

#Molest those that got added without anything good ;_;
$collection->remove(array("md5"=>null));
$int_add--;

echo "Samples Added: <span class='label label-primary'>" . $int_add . "</span><br>";
echo "VT Alerts Deleted: <span class='label label-danger'>"  . $int_del . "</span><br>";


?>
