<?php
require("config.php");

# Mongo connection
$m = new MongoClient("mongodb://".$mongo_server_host.":".$mongo_server_port);
$db = $m->selectDB($mongo_db);
$collection = new MongoCollection($db, "samples");
$tags = new MongoCollection($db, "tags");

$colour = $tags->findOne(array("name"=>$_POST["tag"]))["colour"];

$id = intval($_POST["id"]);
$tag = $_POST["tag"];


function have_Tag($tag_array, $new_tag) {
  foreach ($tag_array as $old_tag) {
    if ($old_tag["name"] == $new_tag) return true;
  }
  return false;
}
print("Finding $id...");
$cursor = $collection->findOne(array("id"=>$id));

if (!array_key_exists("user-tags", $cursor)) {
  $cursor["user-tags"] = array(array("name"=>$tag, "colour"=>$colour));
  $collection->update(array("id"=>$id),
                      $cursor
                      );
} else {
  #Make sure we don't already have it
  if (!have_tag($cursor["user-tags"], $tag)) {
    array_push($cursor["user-tags"], array("name"=>$tag, "colour"=>$colour));

    $collection->update(array("id"=>$id),
                        $cursor
                        );
  }
}

print("Done!");
?>
