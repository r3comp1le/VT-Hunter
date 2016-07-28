function addTag(id) {
    var tags;
    $.ajax({
      type: "GET",
      url: "VT/vt_get_tags.php",
      success: function(data) { console.log(data); tags = JSON.parse(data); },
      async: false
    });
    resp = "<input type='hidden' id='test' value='"+id+"'></input>";
    for (var i = 0; i < tags.length; i++) {
      resp += "<span style='color: "+tags[i]["colour"]+"'>" 
      resp += "<button type='button' class='btn' ";
      resp += "onclick='addTheTag(\"" + tags[i]["name"] + "\")'>"
      resp += "<h4>"+tags[i]["name"]+"</h4></button><br>";
      resp += "</span>"
    }
    resp += "<br><br><h4>Or create a new tag:</h4><br>";
    resp += "<input placeholder='Tag Name' id='cmnt' ></input><br>";
    resp += "<label for='clr'>Colour:</label><input type='color' id='custom' />"
    resp += "<button type='button' class='btn btn-success' ";
    resp += "onclick='addATag("+id+")'>Create</button>";
    $("#modal-bod").html(resp);
    $("#modal-title").html("<h3>Add a tag</h3>");
    $('#scrap_mod').modal('show');

}

function addTheTag(name, id) {
  if (id == null)
    var id = document.getElementById("test").value;
  console.log(id + ", " + name);
  $.ajax({
      type: "POST",
      url: "VT/vt_modify_tag.php",
      data: {tag:name, id:id},
      success: function(data) {
        console.log(data);
        //location.reload();
      },
      async: false
    });
}

function addATag(id) {
    var val = document.getElementById("cmnt").value;
    var col = document.getElementById("custom").value;
    console.log("Adding "+val+" to "+id);
    $.ajax({
      type: "POST",
      url: "VT/vt_add_tag.php",
      data: {colour:col, name:val},
      success: function(data) {
        console.log(data);
        $('#load_mod').modal('hide');

      },
      async: false
    });
    addTheTag(val, id);
    location.reload();
}

function removeTag(id, tag) {
  console.log("Removing " + tag + " from " + id);

  $.ajax({
    type: "POST",
    url: "VT/vt_remove_tag.php",
    data: {id: id, tag:tag},
    async: false,
    success: function(data) {
      console.log(data);
    }
  });

  location.reload();
}

