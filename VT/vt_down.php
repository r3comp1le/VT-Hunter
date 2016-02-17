<?
require('config.php');

#Create Random Folder
function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function rrmdir($dir) {
  if (is_dir($dir)) {
    $objects = scandir($dir);
    foreach ($objects as $object) {
      if ($object != "." && $object != "..") {
        if (filetype($dir."/".$object) == "dir") 
           rrmdir($dir."/".$object); 
        else unlink   ($dir."/".$object);
      }
    }
    reset($objects);
    rmdir($dir);
  }
}

#Clean out DOWNLOADS Folder
rrmdir("DOWNLOADS");

#Get MD5 List
$theMD5s = $_POST['md5Array'];
$folderName = generateRandomString();
$thedir = "DOWNLOADS/".$folderName;

#Check if DIR exist
if (!file_exists($thedir)) 
{
    mkdir($thedir, 0776, true);
}

#Download
foreach ($theMD5s as $md5)
{
    $vt_down = "https://www.virustotal.com/intelligence/download/?hash=".$md5."&apikey=".$vt_mal_key;
    $opts = array(
        'http' => array(
            'method'  => 'GET',
            #'proxy' => 'tcp://proxy.com:5555',
            'request_fulluri' => true,
            )
    );
    $context  = stream_context_create($opts);
    $result = file_get_contents($vt_down, false, $context);

    $destination = $thedir."/".$md5;
    $file = fopen($destination, "w+");
    fputs($file, $result);
    fclose($file);
}

#Zip them all
exec("zip -jrP infected DOWNLOADS/samples.zip " . $thedir);
echo "<center><a href='VT/DOWNLOADS/samples.zip'>Download Link</a></center>";











?>