<?
require('VT/config.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VT Hunter</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" crossorigin="anonymous">
    <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.css">
    
    <script src="https://code.jquery.com/jquery-1.11.3.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==" crossorigin="anonymous"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/bootstrap-table/1.9.1/bootstrap-table.min.js"></script>
</head>

<body>
<style>
    .modal-content {
    width: 900px;
    margin-left: -150px;
    }
    textarea{
    width: 870px;
    height: 300px;
    }
    mark {
    background-color: red;
    color: black;
    } 
    .modal-header {
    padding:9px 15px;
    }
    .container{
        width: 100%;
    }
    .progress-bar.animate {
        width: 100%;
    }
}
</style>
<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <a class="navbar-brand" href="index.php">VT Hunter</a>
      <a class="navbar-brand" href="index.php?archive=true">Archived</a>
      <a class="navbar-brand" href="about.php">About</a>
	  <a class="navbar-brand"><span class="label label-danger"><?echo $version;?></span></a>
	  <a class="navbar-brand"><span class="label label-danger"><?echo $updated;?></span></a>
    </div>
  </div>
</nav>


<div class="container">
<br><br><br><br>
  <h2>Rule Stats</h2>
	<?
	$m = new MongoDB\Client("mongodb://".$mongo_server_host.":".$mongo_server_port);
	$db = $m->selectDB($mongo_db);
	$stats = new MongoCollection($db, $mongo_collection_stats);
	$cursor = $stats->find();
	?>
  <div id="filter-bar"> </div>
<table id='mytable' data-toggle="table" data-classes="table table-hover table-condensed" data-striped="true" data-show-columns="true" data-search="true" data-pagination="true" data-page-size="20" data-sort-name="num" data-sort-order="desc">
<thead>
<tr>
  <th data-field="rule" data-sortable="true">Rule</th>
  <th data-field="num" data-sortable="true">Count</th>
</tr>
</thead>
<tbody>
<?
foreach ($cursor as $array)
{
	print "<tr>";
	print "<td>".$array['rule']."</td>";
	print "<td>".$array['count']."</td>";
	print "</tr>";
}
?>
</tbody>
</table>
</div>

<footer>
<p><center>&copy; r3comp1le 2016</center></p>
</footer>
</div> <!-- /container -->
</body>
</html>
