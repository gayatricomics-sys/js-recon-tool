const API_KEY = "AIzaSyDFAKEKEYFORTESTINGONLY0123456789A";
const config = { apiSecret: "supersecretvalue12345", endpoint: "/api/v1/users" };

function loadUserProfile(userId) {
  return fetch(`/api/v1/users/${userId}/profile`).then((r) => r.json());
}

function search() {
  var params = new URLSearchParams(location.search);
  var q = params.get('q');
  document.getElementById('results').innerHTML = q;
}

function legacyRender(html) {
  document.write(html);
}

axios.post('https://api.example.com/v2/auth/login', { user: 'x' });

function runDynamic(code) {
  eval(code);
}
