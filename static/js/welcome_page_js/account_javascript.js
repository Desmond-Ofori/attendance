const lecturerChoice = document.getElementById('user_choice1');
const studentChoice = document.getElementById('user_choice2');

const createAccountLink = document.querySelector('#create_account a');
const loginLink = document.querySelector('#login a');

const ds = document.body.dataset;
const LECTURER_CREATE = ds.lecturerCreate;
const LECTURER_LOGIN  = ds.lecturerLogin;
const STUDENT_CREATE  = ds.studentCreate;
const STUDENT_LOGIN   = ds.studentLogin;

function setLinks(role) {
  if (role === 'student') {
    createAccountLink.href = STUDENT_CREATE;
    loginLink.href = STUDENT_LOGIN;
  } else {
    createAccountLink.href = LECTURER_CREATE;
    loginLink.href = LECTURER_LOGIN;
  }
}

document.querySelectorAll('input[name="user"]').forEach(radio => {
  radio.addEventListener('change', () => {
    setLinks(studentChoice && studentChoice.checked ? 'student' : 'lecturer');
  });
});

// On load, default to lecturer unless student is preselected
setLinks(studentChoice && studentChoice.checked ? 'student' : 'lecturer');

document.addEventListener('DOMContentLoaded', function() {
  const urlParams = new URLSearchParams(window.location.search);
  const verifyToken = urlParams.get('verify_token');
  if (verifyToken) {
    console.log('[ACCOUNT] Verification token found in URL, processing...');
    window.AuthManager.handleVerification(verifyToken);
  }
});
