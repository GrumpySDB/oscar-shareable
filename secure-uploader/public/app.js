let token = null;
const CONCURRENCY = 5;
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const ALLOWED_EXT = ['edf','crc','tgt'];
const ALWAYS_ACCEPT = ["Identification.crc","Identification.tgt","STR.edf"];
const REQUIRED_FILES = ["config.json","manifest.xml","data.db","metadata.txt"];

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("loginBtn").addEventListener("click", login);
  document.getElementById("uploadBtn").addEventListener("click", uploadFiles);
  document.getElementById("deleteBtn").addEventListener("click", deleteUser);
});

// ---------------- LOGIN ----------------
async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });

  if (!res.ok) return alert("Login failed");

  token = (await res.json()).token;

  document.getElementById("login").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");
}

// ---------------- Helpers ----------------
function withinRange(file, start) {
  const t = file.lastModified;
  const today = new Date();
  today.setHours(23,59,59,999);

  if (start && t < new Date(start).setHours(0,0,0,0)) return false;
  if (t > today.getTime()) return false; // end date always today
  return true;
}

function validFile(file) {
  const ext = file.name.split('.').pop().toLowerCase();
  return ALLOWED_EXT.includes(ext) && file.size <= MAX_FILE_SIZE;
}

// ---------------- UPLOAD ----------------
async function uploadFiles() {
  const username = document.getElementById("uploadUsername").value.trim();
  if (!username) return alert("Please enter a folder name");

  const files = Array.from(document.getElementById("directory").files);
  const start = document.getElementById("startDate").value;

  // ---------------- Fetch existing files ----------------
  let existingFiles = [];
  try {
    const res = await fetch(`/existing-files?username=${encodeURIComponent(username)}`, {
      headers: { "Authorization": "Bearer " + token }
    });
    if (res.ok) {
      existingFiles = await res.json();
      if (!Array.isArray(existingFiles)) existingFiles = [];
    } else {
      console.warn("Could not fetch existing files, status:", res.status);
    }
  } catch(err) {
    console.error("Could not fetch existing files:", err);
    existingFiles = [];
  }

  // ---------------- Filter eligible files ----------------
  const eligible = files.filter(f => {
    const pathInUpload = f.webkitRelativePath;
    if (ALWAYS_ACCEPT.includes(f.name)) return true; // always accept special files
    if (existingFiles.includes(pathInUpload)) return false; // skip existing files
    return (REQUIRED_FILES.includes(f.name) || withinRange(f, start)) && validFile(f);
  });

  if (eligible.length === 0) return alert("No valid files to upload");

  let completed = 0;
  const progressBar = document.getElementById("progressBar");

  async function worker(queue) {
    while (queue.length) {
      const file = queue.pop();
      const formData = new FormData();
      formData.append("file", file);
      formData.append("relativePath", file.webkitRelativePath);
      formData.append("lastModified", file.lastModified);
      formData.append("username", username);

      try {
        const res = await fetch("/upload", {
          method: "POST",
          headers: { "Authorization": "Bearer " + token },
          body: formData
        });
        if (!res.ok) throw new Error(await res.text());
      } catch(err) {
        console.error("Upload failed:", file.name, err);
      }

      completed++;
      progressBar.style.width = ((completed / eligible.length) * 100) + "%";
    }
  }

  const queue = [...eligible];
  await Promise.all(Array(CONCURRENCY).fill().map(() => worker(queue)));

  alert("Upload complete!");
}

// ---------------- DELETE USER DATA ----------------
async function deleteUser() {
  const username = document.getElementById("uploadUsername").value.trim();
  if (!username) return alert("Enter a folder name to delete");

  if (!confirm(`Are you sure you want to delete all data for user "${username}"?`)) return;

  try {
    const res = await fetch("/delete-user", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ username })
    });
    if (res.ok) {
      alert(`User "${username}" data deleted.`);
    } else {
      const text = await res.text();
      alert(`Failed to delete: ${text}`);
    }
  } catch(err) {
    console.error(err);
    alert("Error deleting user data");
  }
}

// ---------------- Initialize start date max/min ----------------
document.addEventListener("DOMContentLoaded", () => {
  const startDateInput = document.getElementById("startDate");
  const today = new Date();
  const oneYearAgo = new Date();
  oneYearAgo.setFullYear(today.getFullYear() - 1);

  startDateInput.max = today.toISOString().split("T")[0];
  startDateInput.min = oneYearAgo.toISOString().split("T")[0];
  startDateInput.value = oneYearAgo.toISOString().split("T")[0];
});
