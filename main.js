import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import { getAuth, GoogleAuthProvider, signInWithPopup } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyAqXR9aF2Bk1wTvWHvQvGS69GI-dNuPd4E",
    authDomain: "login-2dac5.firebaseapp.com",
    projectId: "login-2dac5",
    storageBucket: "login-2dac5.appspot.com",
    messagingSenderId: "10552598791",
    appId: "1:10552598791:web:30c4f0afd3363f3e03a5a2",
    measurementId: "G-19RYRFM900"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// Ensure Firebase authentication language is set to 'en'
auth.languageCode = 'en';

// Initialize Google Auth Provider
const provider = new GoogleAuthProvider();

// Wait for the DOM to be fully loaded
document.addEventListener("DOMContentLoaded", function () {
    const googleLogin = document.getElementById("google-login-btn");

    googleLogin.addEventListener("click", function (event) {
        event.preventDefault(); // Prevent default form submission

        // Perform Google login
        signInWithPopup(auth, provider)
            .then((result) => {
                const user = result.user; // Get user info
                console.log("User signed in:", user);

                // Store user data in local storage for session handling
                localStorage.setItem('user', JSON.stringify(user));

                // Redirect to the home page
                window.location.href = "home.html";
            })
            .catch((error) => {
                const errorCode = error.code;
                const errorMessage = error.message;
                console.error("Error during Google login:", errorCode, errorMessage);

                // Display an error message to the user
                alert("Login failed: " + errorMessage);
            });
    });
});