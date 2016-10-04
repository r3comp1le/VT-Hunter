function conn_test(source){
    $.ajax({
        type: "POST",
        url: "VT/conn_test.php",
        data: {source:source},
        success: function(data){
            alert(data);
        },
    });
}
