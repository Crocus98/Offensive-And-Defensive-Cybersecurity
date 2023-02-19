
    <?php
// Start the session
session_start();
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <title>1024</title>
  <meta name="description" content="1024 game">
  <link rel="icon" href="./icons/ico.png" type="image/x-icon">
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <style>
    <?php 
    $color = $_GET['color'];
    $file = './css/orange.css';
      if ($color != ""){
        $file = './css/'.$color;
      }
      $css = file_get_contents($file);
      echo $css;
     ?>
  </style>

</head>

<body>

  <h1>
    1024 - <a>Play</a> - <a href="viewer.php"> RePlay </a> - <?php 
    if ($color == ""){
      echo '<a href="?color=blue.css" style="color: blue;"> &#x25a0; </a>';
    }
    else {
      echo '<a href="?" style="color: orange;"> &#x25a0; </a>';
    }
    ?>
  </h1>

  <h3>Score: <span id="score">0</h3>

  <div style="margin: 32px; display: flex; justify-content: center">
    <p style="margin: 0">Size:&nbsp</p>
    <input id="size" placeholder="Size" type="number" value="4" style="width: 36px" min="3" max="8"></input>
  </div>
  <div style="margin: 32px; display: flex; justify-content: center">
    <p style="margin: 0">Nickname:&nbsp</p>
    <input id="name" placeholder="Name" type="string" value="Player" style="width: 86px" ></input>
  </div>


  <button class="btn" id="restart">New game</button> <br>
  <button class="btn" id="download"><a style="color: white;" href="./history.php">Download Replay</a></button>
  <table id="tablegame">
    <tr><td><div id="movelist"></div></td>
        <td>
        <canvas width="400" height="400" id="canvas"></canvas>
        </td>
        <td><div id="ranking"></div></td>
    </tr>
  </table>

  <script src="./js/jquery-2.1.1.min.js"></script>
  <script src="./js/hammer.js"></script>
  <script src="./js/script.js"></script>
  <script src="./js/axios.min.js"></script>

</body>

</html>
  