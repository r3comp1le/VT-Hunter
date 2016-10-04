//UI FUNCTIONS FOR VT-HUNTER
function reloadPage(){
    location.reload();
}

function toggle(source) {
    checkboxes = document.getElementsByName('selected');
    for(var i=0, n=checkboxes.length;i<n;i++) {
        checkboxes[i].checked = source.checked;
    }
}

function launch_info_modal(id, title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

            behaviour_dns = "";
            behaviour_http = "";
            url = "";
            sample_info = "";
            alert_info = "";
            debug_name = "";
            debug_signature = "";
            tags = "";

            alert_info =
            "<span class='label label-primary'>Sample Details</span>" +
            "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>MD5</th><td>"+
                  "<a href='https://www.virustotal.com/intelligence/search/"+
                      "?query="+ data.md5 +"#md5'>" + data.md5 + "</a></td></tr>" +
                  "<tr><th>SHA1</th><td>" + data.sha1 + "</td></tr>" +
                  "<tr><th>SHA256</th><td>" + data.sha256 + "</td></tr>" +
                  "<tr><th>First Seen</th><td>" + data.first_seen + "</td></tr>" +
                  "<tr><th>Last Seen</th><td>" + data.last_seen + "</td></tr>" +
                  "<tr><th>File Info</th><td>" + data.type + "</td></tr>" +
                "</tbody>" +
              "</table>";
            if(typeof data.sample_info !== 'undefined')
            {
            trid = data.trid.replace(/\n/g, '<br>');
            try {
                for (i = 0; i < data.behaviour_dns.length; i++)
                {
                    behaviour_dns +=
                    JSON.stringify(data.behaviour_dns[i].ip) +" : " + JSON.stringify(data.behaviour_dns[i].hostname) +"<br>" ;
                }

                for (i = 0; i < data.behaviour_http.length; i++)
                {
                    behaviour_http += JSON.stringify(data.behaviour_http[i].url) +"<br>";
                }

                for (var urls in data.ITW_urls)
                {
                    url += urls + " : " + data.ITW_urls[urls] + "<br>";
                }

                for (var debugs in data.pe_debug['codeview'])
                {
                    debug_name = debugs['name'] + "<br>";
                    debug_signature = debugs['signature'] + "<br>";
                }

                for (i = 0; i < data.tags.length; i++)
                {
                    tags += data.tags[i] + ", ";
                }
            }
            catch(err)
            {
                console.log(err.message);
            }

            sample_info =
            "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>Authentihash</th><td>" + data.authentihash + "</td></tr>" +
                  "<tr><th>Import Hash</th><td><a href='https://www.virustotal.com/intelligence/search/?query=imphash:\""+ data.imphash +"\"'>" + data.imphash + "</a></td></tr>" +
                  "<tr><th>SSDeep</th><td><a href='https://www.virustotal.com/intelligence/search/?query=ssdeep:%22"+ data.ssdeep +" 40%22'>VT Link</a></td></tr>" +
                  "<tr><th>Submission Names</th><td>" + data.submission_names + "</td></tr>" +
                  "<tr><th>Time Submitted</th><td>" + data.times_submitted + "</td></tr>" +
                  "<tr><th>Timestamp</th><td>" + data.timestamp + "</td></tr>" +
                  "<tr><th>Packer</th><td>" + data.unpacker + "</td></tr>" +
                  "<tr><th>Magic</th><td>" + data.magic + "</td></tr>" +
                  "<tr><th>Tags</th><td>" + tags + "</td></tr>" +
                "</tbody>" +
              "</table>" +
            "<span class='label label-primary'>SigCheck</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>Publishers</th><td>" + data.sigcheck_pub + "</td></tr>" +
                  "<tr><th>Verified</th><td>" + data.sigcheck_verified + "</td></tr>" +
                  "<tr><th>Date</th><td>" + data.sigcheck_date + "</td></tr>" +
                  "<tr><th>Signers</th><td>" + data.sigcheck_signers + "</td></tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>TRID</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>" + trid + "</td></tr>" +
                "</tbody>" +
              "</table>" +

              "<span class='label label-primary'>PE Debug</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>Name</td><td>"+debug_name+"</tr>" +
                  "<tr><td>Signature</td><td>"+debug_signature+"</tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>Exif</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><th>TimeStamp</th><td>" + data.exif_TimeStamp + "</td></tr>" +
                  "<tr><th>Language</th><td>" + data.exif_LanguageCode + "</td></tr>" +
                  "<tr><th>File Name</th><td>" + data.exif_OriginalFileName + "</td></tr>" +
                  "<tr><th>Internal Name</th><td>" + data.exif_InternalName + "</td></tr>" +
                  "<tr><th>Product Name</th><td>" + data.exif_ProductName + "</td></tr>" +
                  "<tr><th>Company Name</th><td>" + data.exif_company + "</td></tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>Behaviour</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>UDP</td><td>"+data.behaviour_upd+"</tr>" +
                  "<tr><td>HTTP</td><td>"+behaviour_http+"</tr>" +
                  "<tr><td>DNS</td><td>"+behaviour_dns+"</tr>" +
                  "<tr><td>TCP</td><td>"+data.behaviour_tcp+"</tr>" +
                "</tbody>" +
              "</table>" +

            "<span class='label label-primary'>ITW</span>" +
              "<table class='table table-bordered table-striped table-condensed'>" +
                "<tbody>" +
                  "<tr><td>"+url+"</tr>" +
                "</tbody>" +
              "</table>";
            }
        $("#modal-title").html(title);
        $("#modal-bod").html(
            alert_info +
            sample_info
            );

        $('#scrap_mod').modal('show');
        },
    });
}

function launch_yara_modal(id, title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

        yara = data.match;
        yara0 = yara.replace(/\n/g, "<br>");
        yara1 = yara0.replace(/\*begin_highlight*/g, "<mark>");
        yara2 = yara1.replace(/\*end_highlight*/g, "</mark>");

        $("#modal-bod").html(yara2);
        $("#modal-title").html(title + ' (' + data.date + ')');
        $('#scrap_mod').modal('show');

        },
    });
}

function launch_av_modal(id,title){
    $.ajax({
        type: "POST",
        url: "VT/vt_getcontent.php",
        data: {theId:id},
        success: function(data){

        var av = "";

        for (x in data.scans)
        {
            if(data.scans[x] != null){av += "<b>"+x+"</b>" + ":" + data.scans[x] + "<br>";}
        }

        $("#modal-bod").html(av);
        $("#modal-title").html(title);
        $('#scrap_mod').modal('show');
        },
    });
}
