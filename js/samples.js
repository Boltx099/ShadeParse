// Sample payloads for quick testing
const SAMPLES = {
  secrets: `// === Reconstructed bundle: auth.js ===
const firebaseConfig = {
  apiKey: "AIzaSyD-9tSrke72Mhjk9dKoYQ2zF8M4vkD8Mz",
  authDomain: "prod-app.firebaseapp.com",
  projectId: "prod-app-12345"
};
const STRIPE_SECRET = "sk_live_51HfK2rBKzX4c8Lmn9pQ7xT3yUvW";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const JWT_SECRET = "my-super-secret-jwt-key-2024";
const DB_CONN = "mongodb+srv://admin:Pr0dSecret@cluster0.mongo.net/prod";`,

  xss: `// === Reconstructed bundle: ui.js ===
function renderProfile() {
  const data = location.hash.slice(1);
  document.getElementById('profile').innerHTML = decodeURIComponent(data);
}
function showMsg() {
  const params = new URLSearchParams(location.search);
  const tmpl = params.get('template');
  eval('render(' + tmpl + ')');
}`,

  proto: `// === Reconstructed bundle: utils.js ===
function merge(target, src) {
  for (const key in src) {
    if (src[key] && typeof src[key] === 'object') {
      if (!target[key]) target[key] = {};
      merge(target[key], src[key]);
    } else {
      target[key] = src[key];
    }
  }
  return target;
}
const userInput = JSON.parse(req.body);
merge({}, userInput);`,

  supply: `// === webpack bundle ===
import axios from 'axios';
import colors from 'colors';
import flatmap from 'flatmap-stream';
const CDN_SCRIPT = 'https://cdn.malicious-cdn.io/tracker.js';
document.head.appendChild(Object.assign(document.createElement('script'), { src: CDN_SCRIPT }));`,

  crypto: `// === crypto-utils.js ===
const crypto = require('crypto');
function hashPass(p) { return require('md5')(p); }
function genOTP() { return Math.floor(Math.random() * 999999); }
const cipher = crypto.createCipheriv('des-ecb', '12345678', null);`,

  mega: `// === Full attack surface bundle ===
const STRIPE_KEY = "sk_live_51Hf9KzX4c8L9pQ7x";
function render() {
  document.getElementById('out').innerHTML = location.search.slice(1);
  eval(new URLSearchParams(location.search).get('fn'));
}
deepMerge({}, userInput);
import flatmap from 'flatmap-stream';
function hashPwd(p) { return require('md5')(p); }
const otp = Math.floor(Math.random() * 999999);
if (localStorage.getItem('admin_override') === '1') isAdmin = true;`
};