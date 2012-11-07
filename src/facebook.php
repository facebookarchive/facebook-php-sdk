<?php  
session_start(); // กำหนดไว้ กรณีอาจได้ใช้ตัวแปร session  
include("facebook.php"); //  เรียกใช้งานไฟล์ php-sdk สำหรับ facebook  
  
// สร้าง Application instance.  
$facebook = new facebook(array(  
  'appId'  => '550386494977956', // appid ที่ได้จาก facebook  
  'secret' => 'c9f05bbbafa23e298d6f144a0142aadc', // app secret ที่ได้จาก facebook  
  'cookie' => true, // อนุญาตใช้งาน cookie  
));  

tml  
  
// ตรวจสอบสถานะการ login  
$session = $facebook->getSession();  
  
// สร้างฟังก์ชันไว้สำหรัดทดสอบ การแสดงผลการใช้งาน  
function pre($varUse){  
    echo "<pre>";  
    print_r($varUse);  
    echo "</pre>";  
}  
// สร้างตัวแปรสำหรับเก็บข้อมูลของสมาชิกเมื่อได้ทำการ login แล้ว  
$me = null;   
  
// ถ้ามีการ login ดึงข้อมูลสมาชิกที่ login มาเก็บที่ตัวแปร $me เป็น array  
if ($session) {  
  try {  
    $uid = $facebook->getUser(); // เก็บ id ของผู้ใช้ไว้ที่ตัวแปร $uid กรณีมีการล็อกอิน facebook อยู่  
    $me = $facebook->api('/me'); // ดึงข้อมูลผู้ใช้ปัจจุบันทีล็อกอิน facebook มาเก็บในตัวแปร $me  
  } catch (FacebookApiException $e) { // กรณีเกิดข้อผิดพลากแสดงผลลัพธ์ข้อผิดพลาดที่เกิดขึ้น  
    error_log($e);  
  }  
}  
?>  
<?php  
// ทดสอบการแสดงผลลัพธ์เบื้องต้น เพื่่่อให้แน่ใจว่า พร้อมใช้งาน php-sdk  
pre($session); // แสดงข้อมูลที่จำเป็นในการใช้งาน php-sdk  ตัวแปร เป็น array  
pre($me); // แสดงข้อมูลเบื้องต้นของผู้ใช้ปัจจุบัน ตัวแปร เป็น array  
pre($uid); // แสดง id ของผู้ใช้ปัจจุบัน ตัวแปร เป็น string  
// ข้อมูลข้างต้นจะแสดงเมื่อมีการล็อกอิน facebook อยู่เท่านั้น  
?>  
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  
 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">  
<html xmlns="http://www.w3.org/1999/xhtml"  
 xmlns:fb="http://www.facebook.com/2008/fbml">  
<head>  
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />  
<title>facebook use php sdk</title>  
</head>  
  
<body>  
  
  
  
  
</body>  
</html>  