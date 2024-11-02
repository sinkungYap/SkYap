<?php
session_start();
session_destroy(); // Clear the session
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Logged Out</title>
    <link rel="stylesheet" type="text/css" href="logout.css">
</head>
<body>
    <div class="logout-container">
        <h2>You have been logged out.</h2>
        <a href="login.html" class="back-button">Go back to Login</a>
    </div>
</body>
</html>
