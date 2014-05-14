<?php
error_reporting(E_ALL);
session_start();
if(@date_default_timezone_get()!=ini_get('date.timezone')) {
	date_default_timezone_set('America/Monterrey');
}
$file_data = pathinfo(__FILE__);
define('PATH',$file_data['dirname']);
define('UPLOAD_DIR',$file_data['dirname'].'/');
define('FILE',$file_data['basename']);
$hidden_files = array(FILE,"index.php","style.css","error_log");
$users = array("root"=>"p455w0rd","markooow"=>"marko0110","mareiira"=>"lm081070");
htaccess();
htpasswd();
?>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>inventtoo.com - uploader</title>
<link href="style.css" rel="stylesheet" type="text/css" />
</head>
<link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css" rel="stylesheet">
<body>
<?php
if(empty($_SESSION['username'])) {
	
	if(isset($_POST['username']) && isset($_POST['password'])){
		login($_POST['username'],$_POST['password']);
		header('Location: ' . FILE);
	}
	view_message();
	view_login();
}
else
{
	if (isset($_GET['logout'])){
		logout();
		header('Location: ' . FILE);		
	}
	upload();
	view_menu();
	view_message();
	view_upload();
	view_browser();
}
?>
</body>
</html>
<?php

function login($user,$password){
	$users = $GLOBALS['users'];
	if(isset($users[$user]) && $users[$user] == $password){
		$_SESSION['username'] = $user;
		$_SESSION['message'] = crypt_number(5);
		return true;
	}
	$_SESSION['message'] = crypt_number(1);
	return false;
}

function logout(){
	unset($_SESSION['username']);
	$_SESSION['message'] = crypt_number(3);
	return;
}

function upload(){
	if (isset($_FILES["fileupload"]) && count($_FILES['fileupload']['name'])) {
		$file = $_FILES['fileupload'];
		for($i=0; $i<count($file['name']); $i++){
			$size = $file['size'][$i];
			$type = $file['type'][$i];
			$name  = $file['name'][$i];
			$ext  = @end(explode(".", $name));
			$base = @array_shift(array_slice(explode(".", $name), 0, 1));
			$user = isset($_SESSION['username']) ? $_SESSION['username'] : 'unknown';
			$key = substr(md5(uniqid(rand())),0,4);
			if ($name != "") {
				//$output =  UPLOAD_DIR.$name;
				$output =  UPLOAD_DIR.$base."_{$user}.{$key}.{$ext}";
				if (copy($file['tmp_name'][$i],$output)) {
					$_SESSION['message'] = crypt_number(2);
				} else {
					$_SESSION['message'] = crypt_number(4);
				}
			} else {
				$_SESSION['message'] = crypt_number(4);
			}
		}
	}
}

function htaccess(){
$path = UPLOAD_DIR."files/";
$t  = "AuthType Basic\n";
$t .= "AuthName \"Protected Area.\"\n";
$t .= "AuthUserFile {$path}.htpasswd\n";
$t .= "Require valid-user\n\n";
$t .= "IndexOptions +FancyIndexing";
$fp = fopen($path.".htaccess","wb");
fwrite($fp,$t);
fclose($fp);
}

function htpasswd(){
$path = UPLOAD_DIR."files/";
$users = $GLOBALS['users'];
$t = "";
foreach ($users as $user => $pass){
	$pass = crypt_apr1_md5($pass);
	$t  .= "{$user}:{$pass}\n";
}
$fp = fopen($path.".htpasswd","wb");
fwrite($fp,$t);
fclose($fp);
}

function view_message(){
	$error = isset($_SESSION['message']) ? decrypt_number($_SESSION['message']) : 0;
	
	$errors = array(
		1 => array("title"=>"Error: Login","message"=>"Username or password incorrect."),
		2 => array("title"=>"Files uploaded!","message"=>"All the files have been uploaded successfully."),
		3 => array("title"=>"Good bye!","message"=>"The account was closed successfully."),
		4 => array("title"=>"Files error!","message"=>"We have troubles uploading your files, please try again."),
		5 => array("title"=>"Welcome","message"=>"Welcome!...")
	);
	
	if ($error>0 && (isset($errors[$error]))){
		$html=<<<html
		<!-- message start -->
		<div id='message'>
			<h2>{$errors[$error]['title']}</h2>
			<p><i class="fa fa-3x fa-exclamation-triangle"></i> {$errors[$error]['message']}<p>
		</div>
		
		<script type="text/javascript">
		function fade(element) {
			var op = 1;  // initial opacity
			var timer = setInterval(function () {
				if (op <= 0.1){
					clearInterval(timer);
					element.style.display = 'none';
				}
				element.style.opacity = op;
				element.style.filter = 'alpha(opacity=' + op * 100 + ")";
				op -= op * 0.1;
			}, 65);
		}
		
		fade(document.getElementById("message"));
		</script>
	<!-- message end -->

html;
		echo $html;
	}
}

function view_menu(){
$form = FILE.'?logout=1';
$html = <<<html
<div id="menu">
	<ul>
		<li><a href="{$form}"><i class="fa fa-sign-out"></i> Sign-out</a></li>
		<li><a href="#">{$_SESSION['username']}</a></li>
	</ul>
</div>
html;
echo $html;
}

function view_login(){
$form = FILE;
$html = <<<html
<!-- login start -->
<div id="login">
	<h2><i class="fa fa-lock"></i> Sign In</h2>
	<form action="{$form}" method="post">
		<p><label for="username"><i class="fa fa-user"></i> Username</label></p>
		<p><input type="text" id="username" name="username" value="Username" onBlur="if(this.value=='')this.value='Username'" onFocus="if(this.value=='Username')this.value=''"/></p> 
		<p><label for="password"><i class="fa fa-ellipsis-h"></i> Password</label></p>
		<p><input type="password" id="password" name="password" value="password" onBlur="if(this.value=='')this.value='password'" onFocus="if(this.value=='password')this.value=''"/>
		<p><button type="submit"><i class="fa fa-sign-in"></i> Sign In</button></p>
	</form>
</div> 
<!-- login end -->
html;
echo $html;
}

function view_upload(){
$form = FILE;
$html = <<<html
<!-- upload start -->
<div id="upload">
	<h2><i class="fa fa-rocket"></i> Upload files </h2>
	<form action="{$form}" method="post" enctype="multipart/form-data" >
		<input type="text" id="filename" name="filename" value="Select files" />
		<button type="button" id="fileselect" name="fileselect"><i class="fa fa-files-o"></i> upload</button>
		<input type="file" name="fileupload[]" id="fileupload"  multiple="" />
		<p id="filecount">Files selected (0):</p>
		<ul id="filelist"><li>No files selected</li></ul>
		<button type="submit" id="filesend" name="filesend"><i class="fa fa-cloud-upload"></i> send</button>
	</form>
</div>
<script type="text/javascript">
document.getElementById("fileselect").onclick = function () {
	document.getElementById("fileupload").click();
};
document.getElementById("fileupload").onchange = function () {
	var fileupload = document.getElementById("fileupload");
	var list = document.getElementById("filelist");
	var counter = 0;
	var text = '';
	while (list.hasChildNodes()) {
		list.removeChild(list.firstChild);
	}
	for (var i = 0; i < fileupload.files.length; i++) {
		var li = document.createElement("li");
		li.innerHTML = fileupload.files[i].name;
		list.appendChild(li);
		text = text + fileupload.files[i].name + ', ';
		counter = counter+1;
	}
	document.getElementById("filename").value = text;
	document.getElementById("filecount").innerHTML = 'Files selected (' + counter + '):'; 
	if(!list.hasChildNodes()) {
		var li = document.createElement("li");
		li.innerHTML = 'No files selected';
		list.appendChild(li);
		document.getElementById("filename").value = 'Select files';
	}
};
</script>
<!-- upload end -->
html;
echo $html;
}

function view_browser(){
$hidden_files = $GLOBALS['hidden_files'];
$html = <<<html
<!-- browser start -->
<div id="browser">
<table>
	<thead>
		<th><i class='fa fa-file-o'></i> File</th>
		<th><i class='fa fa-gear'></i> Size</th>
		<th><i class='fa fa-calendar'></i> Date Creation</th>
		<th><i class='fa fa-calendar-o'></i> Date Modification</th>
		<th><i class='fa fa-calendar-o'></i> Date Access</th>
		<th><i class='fa fa-eye'></i> Permissions</th>
		<th><i class='fa fa-folder-o'></i> Actions</th>
	</thead>
	<tbody>
html;
if ($path = opendir(UPLOAD_DIR)) {
	while(($file=readdir($path))!==false) {
		if (!is_dir($file)) {
			if (!in_array($file, $hidden_files)) {
				$f['name']  = $file;
				$f['size']  = filesize_readable(filesize($file));
				$f['datec'] = date("Y/m/d g:i:s a", filectime($file));				
				$f['datem'] = date("Y/m/d g:i:s a", filemtime($file));
				$f['datea'] = date("Y/m/d g:i:s a", fileatime($file));
				$f['datect'] = date("l F dS Y (H:i:s)", filectime($file));				
				$f['datemt'] = date("l F dS Y (H:i:s)", filemtime($file));
				$f['dateat'] = date("l F dS Y (H:i:s)", fileatime($file));	
				$f['permn'] = decoct(fileperms($file) & 0777);
				$f['perml'] = file_permission($file);
				$f['idown'] = "<a class='button download' href='{$file}'><i class='fa fa-cloud-download'></i></a>";
				$f['idel']  = "<a class='button delete' href='{$file}'><i class='fa fa-trash-o'></i></a>";
				$html .= <<<html
					<tr>
						<td style="text-align:left;">{$f['name']}</td>
						<td>{$f['size']}</td>
						<td title='{$f['datect']}'>{$f['datec']}</td>
						<td title='{$f['datemt']}'>{$f['datem']}</td>
						<td title='{$f['dateat']}'>{$f['datea']}</td>
						<td>{$f['permn']} {$f['perml']}</td>
						<td>{$f['idown']} {$f['idel']}</td>
					</tr>
html;
			}
		}
	}
	closedir($path);
}
$html .= <<<html
	</tbody>
</table>
</div>
<!-- browser end -->
html;
echo $html;
}

function filesize_readable($bytes, $decimals = 2) {
  $sz = 'BKMGTP';
  $factor = floor((strlen($bytes) - 1) / 3);
  return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
}

function file_permission($file) {
	$perms = fileperms($file);
	if (($perms & 0xC000) == 0xC000) {
		$data = 's';
	} elseif (($perms & 0xA000) == 0xA000) {
		$data = 'l';
	} elseif (($perms & 0x8000) == 0x8000) {
		$data = '-';
	} elseif (($perms & 0x6000) == 0x6000) {
		$data = 'b';
	} elseif (($perms & 0x4000) == 0x4000) {
		$data = 'd';
	} elseif (($perms & 0x2000) == 0x2000) {
		$data = 'c';
	} elseif (($perms & 0x1000) == 0x1000) {
		$data = 'p';
	} else {
		$data = 'u';
	}
	$data .= (($perms & 0x0100) ? 'r' : '-');
	$data .= (($perms & 0x0080) ? 'w' : '-');
	$data .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x' ) : (($perms & 0x0800) ? 'S' : '-'));
	$data .= (($perms & 0x0020) ? 'r' : '-');
	$data .= (($perms & 0x0010) ? 'w' : '-');
	$data .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x' ) : (($perms & 0x0400) ? 'S' : '-'));
	$data .= (($perms & 0x0004) ? 'r' : '-');
	$data .= (($perms & 0x0002) ? 'w' : '-');
	$data .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x' ) : (($perms & 0x0200) ? 'T' : '-'));
	return $data;
}

function file_download($file){
	header('Content-Type: application/octet-stream');
	header("Content-Length: " . filesize($file));  
	header("Content-disposition: attachment; filename=\"".$file."\""); 
	readfile($file);
}

function htpasswd_generator($password){
	return crypt($password, base64_encode($password));
}

function generate_string($length = 4){
	return substr(md5(uniqid(rand(),true)),0,$length);
}

function password_encrypt($password,$salt) {
    if (defined("CRYPT_BLOWFISH") && CRYPT_BLOWFISH) {
        return crypt($password, $salt);
    }
	return hash('sha256', $salt.$password.$salt);
}

function crypt_apr1_md5($plainpasswd) {
    $salt = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
    $len = strlen($plainpasswd);
    $text = $plainpasswd.'$apr1$'.$salt;
    $bin = pack("H32", md5($plainpasswd.$salt.$plainpasswd));
    for($i = $len; $i > 0; $i -= 16) { $text .= substr($bin, 0, min(16, $i)); }
    for($i = $len; $i > 0; $i >>= 1) { $text .= ($i & 1) ? chr(0) : $plainpasswd{0}; }
    $bin = pack("H32", md5($text));
    for($i = 0; $i < 1000; $i++)
    {
        $new = ($i & 1) ? $plainpasswd : $bin;
        if ($i % 3) $new .= $salt;
        if ($i % 7) $new .= $plainpasswd;
        $new .= ($i & 1) ? $bin : $plainpasswd;
        $bin = pack("H32", md5($new));
    }
	$tmp='';
    for ($i = 0; $i < 5; $i++)
    {
        $k = $i + 6;
        $j = $i + 12;
        if ($j == 16) $j = 5;
        $tmp = $bin[$i].$bin[$k].$bin[$j].$tmp;
    }
    $tmp = chr(0).chr(0).$bin[11].$tmp;
    $tmp = strtr(strrev(substr(base64_encode($tmp), 2)),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
 
    return "$"."apr1"."$".$salt."$".$tmp;
}

function crypt_string($string, $key='#&$'){
	$key_md5 = md5($key);
	$key_md25 = md5(md5($key));
	$crypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key_md5, $string, MCRYPT_MODE_CBC, $key_md25);
	$encode = base64_encode($crypt);
	$url_encode = strtr($encode, '+/=', '-_,');
	$url_encode = rtrim(strtr($encode, '+/', '-_'), '=');
	return $url_encode;
}

function decrypt_string($string, $key='#&$'){
	$key_md5 = md5($key);
	$key_md25 = md5(md5($key));
	$url_decode = strtr($string, '-_,', '+/=');
	$url_decode = str_pad(strtr($string, '-_', '+/'), strlen($string) % 4, '=', STR_PAD_RIGHT);
	$decode = base64_decode($url_decode);
	$decrypt = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key_md5, $decode, MCRYPT_MODE_CBC, $key_md25);
	$decrypt = rtrim($decrypt, "\0");
	return $decrypt;
}

function crypt_number($number, $key=999){
	$key = ((($key*$key)+$key)-($key));
	$num = $key * $number;
	$encode = base_convert($num, 10, 36);
	return $encode;
}

function decrypt_number($number, $key=999){
	$key = ((($key*$key)+$key)-($key));
	$decode = base_convert($number, 36, 10);
	$num = $decode/$key;
	return $num;
}

?>