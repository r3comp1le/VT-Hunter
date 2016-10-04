<?php
function add_event($thejson, $collection, $stats, $taco, $tags) {
    require("config.php");
    $int_add = 0;
    $date = date("F j, Y, g:i a");
    #Extract event info
    $vt_date = $date;
    $vt_first_seen = $thejson['first_seen'];
    $jid = explode("-", $thejson['scan_id']);
    $vt_id = intval($jid[1]);
    $vt_last_seen = $thejson['last_seen'];
    $vt_match = 5;
    $vt_md5 = $thejson['md5'];
    $vt_positives = $thejson['positives'];
    $vt_ruleset_name = "Manual Import";
    $vt_scans = $thejson['scans'];
    $vt_scan = array();
    foreach (array_keys($vt_scans) as $r) {
      $vt_scan[$r] = $vt_scans[$r]["result"];
    }
    $vt_scans = $vt_scan;
    $vt_sha1 = $thejson['sha1'];
    $vt_sha256 = $thejson['sha256'];
    $vt_size = $thejson['size'];
    $vt_subject = "N/A [Manual]";
    $vt_submission_names = $thejson["submission_names"];
    $vt_total = $thejson['total'];
    $vt_type = $thejson['type'];


    # Check if ID exist in DB
    $id_check = array('id' => $vt_id);
    $cursor = $collection->find($id_check);

    if($cursor->count() > 0)
    {
      $sample_details = $cursor->next();
      //Add any tags that don't exist        
      $m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
      $db = $m->selectDB($mongo_db);
     
      if (!is_array($tags)) {
        $tags = explode(",", $tags);
      }
        //Santize
      for ($i = 0; $i < count($tags); $i++) {
        $tags[$i] = array("name"=>$tags[$i], "colour"=>"#ff0000");
      }
      foreach ($tags as $tag) {
        if ($taco->find(array("name"=>$tag["name"]))->count() == 0) {
          $taco->insert($tag);
        }
      }
      $sample_details["user-tags"] = (array_merge($sample_details["user-tags"], $tags));
      $names= array();
      $uniq = array();
      foreach ($sample_details["user-tags"] as $tag) {
        if (!(in_array($tag["name"], $names))) {
           array_push($uniq,  $tag);
           array_push($names, $tag["name"]);
        } 
      }
      $sample_details["user-tags"] = $uniq;
      $collection->update($id_check, $sample_details);

    } else {
      # Check if we've seen the hash before
        $hash_check = array('md5' => $vt_md5);
        $cursor = $collection->find($hash_check);

        if ($cursor->count() != 0) {
            #We've seen the hash before, update the count and all that


        } else {
            #This is a totally new hash, add it normally

            # Add to stats
            $criteria = array('rule' => $vt_ruleset_name);
            $doc = $stats->findOne($criteria);
            if(empty($doc)){
                  $stats->insert(array("count" => 1,"rule" => $vt_ruleset_name));}
            else{$stats->update(array('rule' => $vt_ruleset_name), array('$inc' => array('count' => 1)));}

            $sample_details = array();

            if (isset($thejson['times_submitted'])) {
              $vt_times_submitted = $thejson['times_submitted'];
            } else{
              $vt_times_submitted = "";
            }

            if (isset($thejson['submission_names'])){
              $vt_submission_names = $thejson['submission_names'];
            } else {
              $vt_submission_names = "";}

            if (isset($thejson['additional_info']['trid'])){
              $vt_trid = $thejson['additional_info']['trid'];
            } else {
              $vt_trid = "";}
            if (isset($thejson['additional_info']['pe-debug'])){
              $vt_pe_debug = $thejson['additional_info']['pe-debug'];
            } else {
              $vt_pe_debug = "";}
            if (isset($thejson['additional_info']['pe-imphash'])){
              $vt_imphash = $thejson['additional_info']['pe-imphash'];
            } else {
              $vt_imphash = "";}
            if (isset($thejson['additional_info']['magic'])){
              $vt_magic = $thejson['additional_info']['magic'];
            } else {
              $vt_magic = "";}

            if (isset($thejson['additional_info']['pe-timestamp'])){
              $vt_timestamp = gmdate("Y-m-d\TH:i:s\Z",$thejson['additional_info']['pe-timestamp']);
            } else {
              $vt_timestamp = "";}
            if (isset($thejson['additional_info']['f-prot-unpacker'])){
              $vt_unpacker = $thejson['additional_info']['f-prot-unpacker'];
            } else {
              $vt_unpacker = "";}
            if (isset($thejson['authentihash'])){
              $vt_authentihash = $thejson['authentihash'];
            } else {
              $vt_authentihash = "";}
            if (isset($thejson['resource'])){
              $vt_resource = $thejson['resource'];
            } else {
              $vt_resource = "";}
            if (isset($thejson['ssdeep'])){
              $vt_ssdeep = $thejson['ssdeep'];
            } else {
              $vt_ssdeep = "";}
            if (isset($thejson['ITW_urls'])){
              $vt_ITW_urls = $thejson['ITW_urls'];
            } else {
              $vt_ITW_urls = "";}
            if (isset($thejson['tags'])){
              $vt_tags = $thejson['tags'];
            } else {
              $vt_tags = "";} 

            if (isset($thejson['additional_info']['behaviour-v1']['network']['udp'])){
              $vt_behaviour_udp = $thejson['additional_info']['behaviour-v1']['network']['udp'];
            } else {
              $vt_behaviour_udp = "";}
            if (isset($thejson['additional_info']['behaviour-v1']['network']['http'])){
              $vt_behaviour_http = $thejson['additional_info']['behaviour-v1']['network']['http'];
            } else {
              $vt_behaviour_http = "";}
            if (isset($thejson['additional_info']['behaviour-v1']['network']['dns'])){
              $vt_behaviour_dns = $thejson['additional_info']['behaviour-v1']['network']['dns'];
            } else {
              $vt_behaviour_dns = "";}
            if (isset($thejson['additional_info']['behaviour-v1']['network']['tcp'])){
              $vt_behaviour_tcp = $thejson['additional_info']['behaviour-v1']['network']['tcp'];
            } else {
              $vt_behaviour_tcp = "";}

            if (isset($thejson['additional_info']['sigcheck']['publisher'])){
              $vt_sigcheck_pub = $thejson['additional_info']['sigcheck']['publisher'];
            } else {
              $vt_sigcheck_pub = "";}
            if (isset($thejson['additional_info']['sigcheck']['verified'])){
              $vt_sigcheck_verified = $thejson['additional_info']['sigcheck']['verified'];
            } else {
              $vt_sigcheck_verified = "";}

           if (isset($thejson['additional_info']['sigcheck']['link date'])){
              $vt_sigcheck_date = $thejson['additional_info']['sigcheck']['link date'];
            } else {
              $vt_sigcheck_date = "";}
            if (isset($thejson['additional_info']['sigcheck']['signers'])){
              $vt_sigcheck_signers = $thejson['additional_info']['sigcheck']['signers'];
            } else {
              $vt_sigcheck_signers = "";}

            if (isset($thejson['additional_info']['exiftool']['CompanyName'])){
              $vt_exif_company = $thejson['additional_info']['exiftool']['CompanyName'];
            } else {
              $vt_exif_company = "";}
            if (isset($thejson['additional_info']['exiftool']['LanguageCode'])){
              $vt_exif_LanguageCode = $thejson['additional_info']['exiftool']['LanguageCode'];
            } else {
              $vt_exif_LanguageCode = "";}
            if (isset($thejson['additional_info']['exiftool']['OriginalFileName'])){
              $vt_exif_OriginalFileName = $thejson['additional_info']['exiftool']['OriginalFileName'];
            } else {
              $vt_exif_OriginalFileName = "";}
            if (isset($thejson['additional_info']['exiftool']['TimeStamp'])){
              $vt_exif_TimeStamp = $thejson['additional_info']['exiftool']['TimeStamp'];
            } else {
              $vt_exif_TimeStamp = "";}
            if (isset($thejson['additional_info']['exiftool']['InternalName'])){
              $vt_exif_InternalName = $thejson['additional_info']['exiftool']['InternalName'];
            } else {
              $vt_exif_InternalName= "";}
            if (isset($thejson['additional_info']['exiftool']['ProductName'])){
              $vt_exif_ProductName = $thejson['additional_info']['exiftool']['ProductName'];
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

        //Add any tags that don't exist        
        $m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
        $db = $m->selectDB($mongo_db);
        $tags = explode(",", $tags);
        //Santize
        for ($i = 0; $i < count($tags); $i++) {
          $tags[$i] = array("name"=>$tags[$i], "colour"=>"#ff0000");
        }
        foreach ($tags as $tag) {
          if ($taco->find(array("name"=>$tag["name"]))->count() == 0) {
            $taco->insert($tag);
          } 
        }
        $sample_details["user-tags"] =$tags;


        $sample_details = array_merge($sample_details, $sample_alert_info);

        $collection->insert($sample_details);
        $int_add++;

        }    
    }
    
    return $int_add;     
}

?>
