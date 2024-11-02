<?php
$to = 'recipient@example.com'; // Replace with your email address
$subject = 'Test Email';
$message = 'This is a test email sent using PHP mail function.';
$headers = 'From: yapnc1008@gmail.com' . "\r\n" .
           'Reply-To: yapnc1008@gmail.com';

if (mail($to, $subject, $message, $headers)) {
    echo 'Email sent successfully!';
} else {
    echo 'Email sending failed!';
}
?>