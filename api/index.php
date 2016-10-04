<?php
include "../VT/config.php"; 
include "../VT/utils.php";
include "../VT/vt_import_api.php";

# Set up base response array. 
# 0 => NO ERROR
# 1 => ERROR. Implies existence of MESSAGE
$response = Array("status"=>0);

function error($msg, $resp) {
    $resp["message"] = $msg;
    $resp["status"]  = 1;
    respond($resp);
}

function success($msg, $resp) {
    $resp["message"] = $msg;
    respond($resp);
}

function respond($resp) {
    print(json_encode($resp));
    die;
}

if (!isset($_GET["action"])) {
    error("No action provided!", $response);
}

switch ($_GET["action"]) {
    case "importhash":
        if (!isset($_GET["resource"])) {
            error("Please provide a hash to import.", $response);
        }
    
        $hash = $_GET["resource"];
        
        # Check that it is a hash
        if (!preg_match("/([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})/", $hash)) {
            error("That Hash doesn't seem valid! We accept MD5, SHA1 and SHA256.", $response);
        }
        
        $response["imported"] = $hash;

        if (isset($_GET["tags"])) {
            $tags = $_GET["tags"];
        } else {
            $tags = array();
        }
    
        # Import the hash
        $code = importHash($hash, $tags);
    
        if ($code == 0) {
            success("Hash Imported.", $response);
        } else {
            error("Hash failed to import.", $response);
        }
        break;

    default:
        error("That action isn't valid!", $response);
        break;

}

?>
