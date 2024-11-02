<?php
// Start session
session_start();

// Database connection
$conn = new mysqli("localhost", "root", "", "login_system");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = trim($_POST['email']); // Trim whitespace
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm-password'];

    // Validate email format
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email format. Please enter a valid email!'); window.history.back();</script>";
        exit();
    }

    if (empty($email)) {
        echo "<script>alert('Email is empty. Please enter your email!'); window.history.back();</script>";
        exit();
    }

    // Check if password and confirm password match
    if ($password !== $confirm_password) {
        echo "<script>alert('Passwords do not match. Please try again!'); window.history.back();</script>";
        exit();
    }

    // Check password length
    if (strlen($password) < 8) {
        echo "<script>alert('Password must be at least 8 characters long.'); window.history.back();</script>";
        exit();
    }

    // Hash the password securely
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepared statement to check if email already exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        echo "<script>alert('Email already taken, please choose another.'); window.history.back();</script>";
        exit();
    }

    // Prepared statement to insert a new user
    $stmt = $conn->prepare("INSERT INTO users (email, password) VALUES (?, ?)");
    if (!$stmt) {
        echo "<script>alert('Error preparing statement: " . $conn->error . "'); window.history.back();</script>";
        exit();
    }
    $stmt->bind_param("ss", $email, $hashed_password);

    // Execute the prepared statement
    if ($stmt->execute()) {
        // Redirect to the login page after successful sign up
        header('Location: login.html'); // Server-side redirect
        exit();
    } else {
        // Log the error and show a generic error message
        error_log("Database error: " . $stmt->error);
        echo "<script>alert('An error occurred. Please try again later.'); window.history.back();</script>";
        exit();
    }

    $stmt->close();
}

$conn->close();
?>
