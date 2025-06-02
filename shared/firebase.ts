import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";
import { getAuth } from "firebase/auth";
import { getAnalytics, isSupported } from "firebase/analytics";

const firebaseConfig = {
  apiKey: "AIzaSyBp1F5fwMA3vAQRNmQKrTFoBAz--OTUdoQ",
  authDomain: "cybershield-a0ee3.firebaseapp.com",
  projectId: "cybershield-a0ee3",
  storageBucket: "cybershield-a0ee3.firebasestorage.app",
  messagingSenderId: "690531886211",
  appId: "1:690531886211:web:7f8b486292e6c6aa4b67b6",
  measurementId: "G-7LH4J13B6N"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
export const auth = getAuth(app);

// Initialize Analytics only in browser environment
export const analytics = typeof window !== 'undefined' ? getAnalytics(app) : null; 