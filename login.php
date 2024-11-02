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
    $email = trim($_POST['email']);
    $password = trim($_POST['password']); 

    // Check if email and password are not empty
    if (empty($email) || empty($password)) {
        echo "<script>
                alert('Email and password are required!');
                window.history.back();
                document.getElementById('password').value = ''; // Clear password input
              </script>";
        exit();
    }

    // Prepare and execute the SQL query to select the user based on email
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    

    // Check if user exists
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();

        // Verify the password
        if (password_verify($password, $row['password'])) {
            // Password is correct, set session variables
            $_SESSION['email'] = $email;

            // Regenerate session ID for security
            session_regenerate_id();

            // Redirect to home page
            header("Location: home.html");
            exit();
        } else {
            // Incorrect password, clear password input
            echo "<script>
                    alert('Invalid email or password! Please try again!');
                    window.history.back();
                    document.getElementById('password').value = ''; // Clear password input
                  </script>";
        }
    } else {
        // User not found, clear password input
        echo "<script>
                alert('Invalid email or password! Please try Again!');
                window.history.back();
                document.getElementById('password').value = ''; // Clear password input
              </script>";
    }

    $stmt->close();
}

$conn->close();
?>
