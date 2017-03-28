<?php
$from=$_POST['email'];
$email="casian_gheorghe@yahoo.com";
$date=$_POST['date'];
$time=$_POST['ora'];
$tel=$_POST['tel'];
$message=$_POST['mesage'];

mail($email, $date, $time, $tel, $message, "From:" $from);

print "Mesajul tau a fost expediat cu succes!!!" </br>$email</br>$date</br>$time</br>$tel</br>$message</p>

?>
