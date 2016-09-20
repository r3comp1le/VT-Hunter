<?php
#Mongo Config
$mongo_server_host = "127.0.0.1";
$mongo_server_port = "27017";
$mongo_db = "vt";
$mongo_collection = "samples";
$mongo_collection_stats = "stats";
$mongo_collection_tags = "tags";

#Crits Connections
$crits_on = "false";
$crits_url = ""; 
$crits_api_key = "";
$crits_user = "";

#MISP Connections
$misp_on = "false";

$misp_url = "";
$misp_api_key = "";

#Viper Connections
$viper_on = "false";
$viper_url = "http://viper.li:8080";
$viper_api_url = "http://viper.li:9090";

#VT 
#VirusTotal Intelligence API
$vt_mal = "false";  
$vt_mal_key = "";

#VirusTotal Private Mass API
$vt_search = "false"; 
$vt_search_key = "";

$delete_alerts = "false";

#Version
$version = "2.8";
$updated = "20 Sep 2016";

#AV
$av_vendor = array("ESET-NOD32","TrendMicro","Sophos","McAfee",
                    "Kaspersky", "Fortinet",  "Ikarus","Symantec",
                    "Qihoo-360");

$av_multiple = is_array($av_vendor);

#Allow Manual Pull of VT, MISP, CRITS
$manual_pull = "true";
?>
