// Import the functions you need from the SDKs you need
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";

// TODO: Replace the following with your app's Firebase project configuration
// You can find this in the Firebase Console -> Project Settings -> General -> Your apps
const firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_PROJECT_ID.firebaseapp.com",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_PROJECT_ID.appspot.com",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const provider = new GoogleAuthProvider();

// DOM Elements
const loginCard = document.getElementById('login-card');
const userInfo = document.getElementById('user-info');
const googleLoginBtn = document.getElementById('google-login-btn');
const logoutBtn = document.getElementById('logout-btn');
const userNameDisplay = document.getElementById('user-name');
const userEmailDisplay = document.getElementById('user-email');
const userAvatarDisplay = document.getElementById('user-avatar');
const btnLoader = document.getElementById('btn-loader');
const btnText = googleLoginBtn.querySelector('span');

// Authentication State Observer
onAuthStateChanged(auth, (user) => {
    if (user) {
        // User is signed in
        showUserInfo(user);
    } else {
        // User is signed out
        showLogin();
    }
});

// Login Function
googleLoginBtn.addEventListener('click', () => {
    setLoading(true);
    signInWithPopup(auth, provider)
        .then((result) => {
            // This gives you a Google Access Token. You can use it to access the Google API.
            const credential = GoogleAuthProvider.credentialFromResult(result);
            const token = credential.accessToken;
            // The signed-in user info.
            const user = result.user;
            console.log("User signed in:", user);
            // UI updates are handled by onAuthStateChanged
        }).catch((error) => {
            // Handle Errors here.
            const errorCode = error.code;
            const errorMessage = error.message;
            console.error("Login Error:", errorCode, errorMessage);
            alert(`Login Failed: ${errorMessage}`);
            setLoading(false);
        });
});

// Logout Function
logoutBtn.addEventListener('click', () => {
    signOut(auth).then(() => {
        // Sign-out successful.
        console.log("User signed out");
    }).catch((error) => {
        // An error happened.
        console.error("Logout Error:", error);
    });
});

// UI Helper Functions
function showUserInfo(user) {
    loginCard.style.display = 'none';
    userInfo.style.display = 'block';

    userNameDisplay.textContent = user.displayName;
    userEmailDisplay.textContent = user.email;
    userAvatarDisplay.src = user.photoURL;

    // Reset button state just in case
    setLoading(false);
}

function showLogin() {
    loginCard.style.display = 'block';
    userInfo.style.display = 'none';
}

function setLoading(isLoading) {
    if (isLoading) {
        btnLoader.style.display = 'block';
        btnText.style.display = 'none';
        googleLoginBtn.style.pointerEvents = 'none';
        googleLoginBtn.style.opacity = '0.8';
    } else {
        btnLoader.style.display = 'none';
        btnText.style.display = 'block';
        googleLoginBtn.style.pointerEvents = 'auto';
        googleLoginBtn.style.opacity = '1';
    }
}
