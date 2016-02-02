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
    
    <script src="http://code.jquery.com/jquery-1.11.3.min.js"></script>
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
      <a class="navbar-brand" href="vt.php">VT Hunter</a>
      <a class="navbar-brand" href="vt.php?archive=true">Archived</a>
      <a class="navbar-brand" href="about.php">About</a>
    </div>
  </div>
</nav>


<div class="container">
<br><br><br><br>
  <p>A Web Interface to Manage VT Alerts</p>            
  <table class="table table-hover table-bordered">
    <thead>
      <tr>
        <th>Version</th>
        <td><?echo $version;?></td>
      </tr>
    </thead>
    <tbody>
      <tr>
        <th>Last Updated</th>
        <td><?echo $updated;?></td>
      </tr>
    </tbody>
  </table>
</div>

<footer>
<p><center>&copy; r3comp1le 2016</center></p>
</footer>
</div> <!-- /container -->
</body>
</html>
