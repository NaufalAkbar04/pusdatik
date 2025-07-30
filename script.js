// --- Konstanta dan Elemen DOM ---
const userEmailInput = document.getElementById('userEmail');
const masterPasswordInput = document.getElementById('masterPassword');
const loginBtn = document.getElementById('loginBtn');
const registerBtn = document.getElementById('registerBtn');
const authSection = document.getElementById('auth-section');
const mainApp = document.getElementById('main-app'); // ID baru untuk container utama setelah login
const loggedInUserEmailSpan = document.getElementById('loggedInUserEmail'); // Untuk menampilkan email user
const logoutBtn = document.getElementById('logoutBtn');

const createRecordBtn = document.getElementById('createRecordBtn');
const searchTermInput = document.getElementById('searchTerm');
const recordList = document.getElementById('recordList');
const recordCountSpan = document.getElementById('recordCount');

const vaultListView = document.getElementById('vault-list-view');
const recordFormView = document.getElementById('record-form-view');

const formRecordId = document.getElementById('recordId'); // Hidden input for record ID
const formTitle = document.getElementById('formTitle');
const formRecordType = document.getElementById('formRecordType');
const formTitleInput = document.getElementById('formTitleInput');
const formLoginInput = document.getElementById('formLoginInput');
const formPasswordInput = document.getElementById('formPasswordInput');
const formWebsiteAddress = document.getElementById('formWebsiteAddress');
const cancelFormBtn = document.getElementById('cancelFormBtn');
const saveRecordBtn = document.getElementById('saveRecordBtn');

const passwordToggleBtn = document.querySelector('.password-toggle-btn');
const passwordGenerateBtn = document.querySelector('.password-generate-btn');
const passwordStrengthMeter = document.querySelector('.password-strength-meter');
const strengthBar = document.querySelector('.strength-bar');
const strengthText = document.querySelector('.strength-text');
const passwordOptions = document.querySelector('.password-options');
const passwordLengthSlider = document.getElementById('passwordLengthSlider');
const passwordLengthValue = document.getElementById('passwordLengthValue');
const includeAZ = document.getElementById('includeAZ');
const include09 = document.getElementById('include09');
const includeSpecial = document.getElementById('includeSpecial');

// --- Variabel Global ---
let encryptionKey = null; // Kunci enkripsi akan disimpan di sini setelah login
let vaultData = {}; // Data brankas yang didekripsi
let currentUserId = null; // ID pengguna yang sedang login
let currentSessionId = null; // ID sesi dari backend

const BACKEND_URL = 'http://127.0.0.1:5000';
const ITERATIONS = 480000;

// --- Fungsi Kriptografi (Menggunakan Web Crypto API) ---
function generateSalt(length = 16) { return window.crypto.getRandomValues(new Uint8Array(length)); }
function strToBuf(str) { return new TextEncoder().encode(str); }
function bufToStr(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))); }
function strToBufB64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }

async function deriveKey(masterPassword, salt) {
    const passwordBuffer = strToBuf(masterPassword);
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", passwordBuffer, { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );
    const aesKey = await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: ITERATIONS, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
    return aesKey;
}

async function encryptData(data, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, key, strToBuf(data)
    );
    const fullEncrypted = new Uint8Array(iv.length + encryptedContent.byteLength);
    fullEncrypted.set(iv, 0);
    fullEncrypted.set(new Uint8Array(encryptedContent), iv.length);
    return bufToStr(fullEncrypted);
}

async function decryptData(encryptedB64, key) {
    try {
        const fullEncrypted = strToBufB64(encryptedB64);
        const iv = fullEncrypted.slice(0, 12);
        const encryptedContent = fullEncrypted.slice(12);
        const decryptedContent = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, key, encryptedContent
        );
        return new TextDecoder().decode(decryptedContent);
    } catch (e) {
        console.error("Dekripsi gagal:", e);
        return null;
    }
}

// --- Fungsi Aplikasi Utama ---

async function handleLogin() {
    const email = userEmailInput.value.trim();
    const masterPassword = masterPasswordInput.value;

    if (!email || !masterPassword) {
        alert("Email dan Kata Sandi Utama harus diisi.");
        return;
    }

    try {
        const response = await fetch(`${BACKEND_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email }),
        });

        const data = await response.json();

        if (response.ok) {
            currentUserId = data.userId;
            currentSessionId = data.sessionId;
            loggedInUserEmailSpan.textContent = email; // Tampilkan email pengguna
            const salt = strToBufB64(data.masterSalt);
            
            encryptionKey = await deriveKey(masterPassword, salt);
            const decryptedVault = await decryptData(data.encryptedVaultBlob, encryptionKey);

            if (decryptedVault !== null) {
                // Konversi data brankas dari objek menjadi array untuk CRUD yang lebih mudah
                vaultData = Object.values(JSON.parse(decryptedVault));
                renderRecordList();
                showMainApp();
                alert("Login berhasil!");
            } else {
                alert("Kata sandi utama salah atau data brankas rusak.");
                encryptionKey = null; vaultData = {}; currentUserId = null; currentSessionId = null;
            }
        } else {
            alert(data.message || "Gagal login.");
        }
    } catch (e) {
        console.error("Kesalahan jaringan atau server:", e);
        alert("Terjadi kesalahan saat menghubungi server. Pastikan backend berjalan.");
    }
}

async function handleRegister() {
    const email = userEmailInput.value.trim();
    const masterPassword = masterPasswordInput.value;

    if (!email || !masterPassword || masterPassword.length < 8) {
        alert("Email harus diisi dan Kata Sandi Utama minimal 8 karakter.");
        return;
    }

    const salt = generateSalt();
    const initialEncryptionKey = await deriveKey(masterPassword, salt);
    const initialEncryptedVaultBlob = await encryptData(JSON.stringify({}), initialEncryptionKey);

    try {
        const response = await fetch(`${BACKEND_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: email,
                masterSalt: bufToStr(salt),
                initialVaultBlob: initialEncryptedVaultBlob
            }),
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message + " Sekarang silakan Login.");
            masterPasswordInput.value = '';
        } else {
            alert(data.message || "Gagal mendaftar.");
        }
    } catch (e) {
        console.error("Kesalahan jaringan atau server:", e);
        alert("Terjadi kesalahan saat menghubungi server. Pastikan backend berjalan.");
    }
}

async function saveVaultToBackend() {
    if (!encryptionKey || !currentUserId || !currentSessionId) {
        console.error("Tidak ada kunci enkripsi atau pengguna/sesi tidak valid.");
        return;
    }
    try {
        // Konversi array vaultData kembali ke objek sebelum dienkripsi
        const vaultDataAsObject = vaultData.reduce((obj, item) => {
            obj[item.id] = item; // Gunakan ID sebagai kunci objek
            return obj;
        }, {});

        const encryptedVaultBlob = await encryptData(JSON.stringify(vaultDataAsObject), encryptionKey);
        const response = await fetch(`${BACKEND_URL}/vault`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': currentSessionId
            },
            body: JSON.stringify({ encryptedVaultBlob: encryptedVaultBlob }),
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error("Gagal menyimpan brankas ke backend:", errorData.message);
            alert("Gagal menyimpan perubahan brankas.");
        } else {
            console.log("Brankas berhasil disimpan ke backend.");
        }
    } catch (e) {
        console.error("Kesalahan jaringan saat menyimpan brankas:", e);
        alert("Terjadi kesalahan jaringan saat menyimpan brankas.");
    }
}

async function handleLogout() {
    try {
        await fetch(`${BACKEND_URL}/logout`, {
            method: 'POST',
            headers: { 'Authorization': currentSessionId }
        });
    } catch (e) {
        console.error("Gagal logout dari backend:", e);
    }
    showAuth();
}

function showMainApp() {
    authSection.style.display = 'none';
    mainApp.style.display = 'flex'; // Menggunakan flex untuk layout utama
    masterPasswordInput.value = '';
    userEmailInput.value = '';
    // Atur tampilan awal ke daftar record
    showView('my-vault');
}

function showAuth() {
    authSection.style.display = 'block';
    mainApp.style.display = 'none';
    vaultData = {}; encryptionKey = null; currentUserId = null; currentSessionId = null;
    loggedInUserEmailSpan.textContent = '';
    renderRecordList(); // Bersihkan tampilan list
}

function showView(viewId) {
    // Sembunyikan semua view konten
    vaultListView.style.display = 'none';
    recordFormView.style.display = 'none';

    // Tampilkan view yang diminta
    if (viewId === 'my-vault') {
        vaultListView.style.display = 'block';
        renderRecordList(searchTermInput.value); // Render ulang daftar jika ke my-vault
    } else if (viewId === 'record-form') {
        recordFormView.style.display = 'block';
    }
    // Implementasi untuk view lain (banking, identity, dll.) bisa ditambahkan di sini.
    // Untuk demo ini, hanya my-vault dan record-form yang berfungsi penuh.

    // Update active class di sidebar
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.view === viewId) {
            item.classList.add('active');
        }
    });
}

// --- CRUD Operations ---

// CREATE / UPDATE
async function saveRecord() {
    const id = formRecordId.value || crypto.randomUUID(); // Buat ID baru jika ini record baru
    const title = formTitleInput.value.trim();
    const login = formLoginInput.value.trim();
    const password = formPasswordInput.value; // Ambil nilai mentah dari input
    const website = formWebsiteAddress.value.trim();

    if (!title || !login || !password) {
        alert("Judul, Login, dan Kata Sandi wajib diisi.");
        return;
    }

    const encryptedPassword = await encryptData(password, encryptionKey);

    const newRecord = {
        id: id,
        type: formRecordType.value, // Default 'login'
        title: title,
        username: login,
        password: encryptedPassword, // Simpan yang sudah dienkripsi
        website: website
    };

    const existingIndex = vaultData.findIndex(record => record.id === id);
    if (existingIndex > -1) {
        // Update existing record
        vaultData[existingIndex] = newRecord;
    } else {
        // Add new record
        vaultData.push(newRecord);
    }

    await saveVaultToBackend();
    renderRecordList();
    showView('my-vault'); // Kembali ke daftar setelah menyimpan
    alert("Record berhasil disimpan!");
}

// READ (Render List)
function renderRecordList(filterTerm = '') {
    recordList.innerHTML = '';
    const filteredRecords = vaultData.filter(record =>
        record.title.toLowerCase().includes(filterTerm.toLowerCase()) ||
        record.username.toLowerCase().includes(filterTerm.toLowerCase()) ||
        record.website.toLowerCase().includes(filterTerm.toLowerCase())
    );

    recordCountSpan.textContent = filteredRecords.length; // Update jumlah record

    if (filteredRecords.length === 0) {
        const li = document.createElement('li');
        li.classList.add('empty-list-message');
        li.textContent = filterTerm ? "Tidak ditemukan record untuk pencarian Anda." : "Tidak ada record. Klik 'Create New' untuk menambahkan.";
        recordList.appendChild(li);
        return;
    }

    filteredRecords.forEach(record => {
        const li = document.createElement('li');
        li.dataset.id = record.id; // Simpan ID record di elemen LI

        li.innerHTML = `
            <i class="fas fa-desktop record-icon"></i> <div class="record-details">
                <strong>${record.title}</strong>
                <span>${record.username}</span>
            </div>
            <div class="record-actions">
                <button class="edit-record-btn"><i class="fas fa-edit"></i> Edit</button>
                <button class="copy-username-btn"><i class="fas fa-user"></i> Salin User</button>
                <button class="copy-password-btn"><i class="fas fa-key"></i> Salin Pass</button>
                <button class="delete-record-btn"><i class="fas fa-trash-alt"></i> Hapus</button>
            </div>
        `;
        recordList.appendChild(li);
    });
    addRecordListEventListeners(); // Tambahkan event listener setelah semua li dibuat
}

function addRecordListEventListeners() {
    // Event listener untuk klik pada item daftar (untuk melihat detail/edit)
    recordList.querySelectorAll('li').forEach(li => {
        li.addEventListener('click', (event) => {
            // Pastikan klik tidak berasal dari tombol aksi
            if (!event.target.closest('.record-actions')) {
                const recordId = li.dataset.id;
                editRecord(recordId);
            }
        });
    });

    // Event listener untuk tombol Edit
    recordList.querySelectorAll('.edit-record-btn').forEach(button => {
        button.onclick = (event) => {
            event.stopPropagation(); // Stop propagation to prevent li click
            const recordId = event.target.closest('li').dataset.id;
            editRecord(recordId);
        };
    });

    // Event listener untuk tombol Salin Username
    recordList.querySelectorAll('.copy-username-btn').forEach(button => {
        button.onclick = (event) => {
            event.stopPropagation();
            const recordId = event.target.closest('li').dataset.id;
            const record = vaultData.find(r => r.id === recordId);
            if (record && record.username) {
                navigator.clipboard.writeText(record.username)
                    .then(() => alert('Username disalin!'))
                    .catch(err => console.error('Gagal menyalin:', err));
            }
        };
    });

    // Event listener untuk tombol Salin Password
    recordList.querySelectorAll('.copy-password-btn').forEach(button => {
        button.onclick = async (event) => {
            event.stopPropagation();
            const recordId = event.target.closest('li').dataset.id;
            const record = vaultData.find(r => r.id === recordId);
            if (record && record.password) {
                const decryptedPass = await decryptData(record.password, encryptionKey);
                if (decryptedPass) {
                    navigator.clipboard.writeText(decryptedPass)
                        .then(() => alert('Kata Sandi disalin!'))
                        .catch(err => console.error('Gagal menyalin:', err));
                }
            }
        };
    });

    // Event listener untuk tombol Hapus
    recordList.querySelectorAll('.delete-record-btn').forEach(button => {
        button.onclick = async (event) => {
            event.stopPropagation();
            const recordId = event.target.closest('li').dataset.id;
            deleteRecord(recordId);
        };
    });
}

// UPDATE (Load data ke form)
async function editRecord(id) {
    const recordToEdit = vaultData.find(record => record.id === id);
    if (recordToEdit) {
        formRecordId.value = recordToEdit.id;
        formTitle.textContent = "Edit Record";
        formRecordType.value = recordToEdit.type || 'login';
        formTitleInput.value = recordToEdit.title;
        formLoginInput.value = recordToEdit.username;
        formWebsiteAddress.value = recordToEdit.website;

        // Dekripsi password untuk ditampilkan di form (sebagai text, tapi bisa diubah jadi password type)
        const decryptedPass = await decryptData(recordToEdit.password, encryptionKey);
        formPasswordInput.value = decryptedPass || '';
        formPasswordInput.type = 'password'; // Pastikan kembali ke password type
        passwordToggleBtn.innerHTML = '<i class="fas fa-eye"></i>'; // Reset ikon toggle

        passwordStrengthMeter.style.display = 'none'; // Sembunyikan saat edit
        passwordOptions.style.display = 'none'; // Sembunyikan saat edit

        showView('record-form');
    } else {
        alert("Record tidak ditemukan.");
    }
}

// DELETE
async function deleteRecord(id) {
    if (confirm("Apakah Anda yakin ingin menghapus record ini?")) {
        vaultData = vaultData.filter(record => record.id !== id);
        await saveVaultToBackend();
        renderRecordList(searchTermInput.value);
        alert("Record berhasil dihapus!");
    }
}

// --- Password Generator & Strength Meter ---
function checkPasswordStrength(password) {
    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) score += 1;

    let strength = "Sangat Lemah";
    let color = "#dc3545"; // Red
    let width = (score / 6) * 100;

    if (score === 0) {
        strength = "Sangat Lemah"; width = 0;
    } else if (score <= 2) {
        strength = "Lemah"; color = "#ffc107"; // Orange
    } else if (score <= 4) {
        strength = "Sedang"; color = "#ffeb3b"; // Yellow
    } else if (score === 5) {
        strength = "Kuat"; color = "#28a745"; // Green
    } else if (score === 6) {
        strength = "Sangat Kuat"; color = "#17a2b8"; // Cyan
    }

    strengthBar.style.width = `${width}%`;
    strengthBar.style.backgroundColor = color;
    strengthText.textContent = strength;

    passwordStrengthMeter.style.display = 'flex'; // Tampilkan meter
}

function generatePassword(length, useAZ, use09, useSpecial) {
    let charset = "";
    if (useAZ) charset += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (use09) charset += "0123456789";
    if (useSpecial) charset += "!@#$%^&*()-_=+[]{}|;:',.<>?"; // Karakter khusus yang lebih lengkap
    
    if (charset.length === 0) {
        alert("Pilih setidaknya satu jenis karakter untuk menghasilkan kata sandi.");
        return "";
    }

    let password = "";
    const randomValues = new Uint32Array(length);
    window.crypto.getRandomValues(randomValues);

    for (let i = 0; i < length; i++) {
        password += charset[randomValues[i] % charset.length];
    }
    return password;
}

// --- Event Listeners ---
loginBtn.addEventListener('click', handleLogin);
registerBtn.addEventListener('click', handleRegister);
logoutBtn.addEventListener('click', handleLogout);

createRecordBtn.addEventListener('click', () => {
    // Reset form untuk membuat record baru
    formRecordId.value = '';
    formTitle.textContent = "New Record";
    formRecordType.value = 'login';
    formTitleInput.value = '';
    formLoginInput.value = '';
    formPasswordInput.value = '';
    formWebsiteAddress.value = '';

    formPasswordInput.type = 'password'; // Pastikan kembali ke password type
    passwordToggleBtn.innerHTML = '<i class="fas fa-eye"></i>'; // Reset ikon toggle
    passwordStrengthMeter.style.display = 'none'; // Sembunyikan meter
    passwordOptions.style.display = 'block'; // Tampilkan opsi generator

    // Reset generator options
    passwordLengthSlider.value = 16;
    passwordLengthValue.textContent = 16;
    includeAZ.checked = true;
    include09.checked = true;
    includeSpecial.checked = true;

    showView('record-form');
});

cancelFormBtn.addEventListener('click', () => {
    showView('my-vault');
});

saveRecordBtn.addEventListener('click', saveRecord);

searchTermInput.addEventListener('input', () => {
    renderRecordList(searchTermInput.value);
});

// Event listener untuk nav item di sidebar
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        // Untuk demo ini, hanya "My Vault" yang fungsional
        if (item.dataset.view === 'my-vault') {
            showView('my-vault');
        } else {
            alert(`Fitur '${item.textContent.trim()}' tidak diimplementasikan dalam demo ini.`);
        }
    });
});

// Password form field interactivity
passwordToggleBtn.addEventListener('click', () => {
    const type = formPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    formPasswordInput.setAttribute('type', type);
    passwordToggleBtn.innerHTML = type === 'password' ? '<i class="fas fa-eye"></i>' : '<i class="fas fa-eye-slash"></i>';
});

passwordGenerateBtn.addEventListener('click', () => {
    const length = parseInt(passwordLengthSlider.value);
    const generatedPass = generatePassword(
        length,
        includeAZ.checked,
        include09.checked,
        includeSpecial.checked
    );
    formPasswordInput.value = generatedPass;
    checkPasswordStrength(generatedPass); // Cek kekuatan password yang baru dibuat
    formPasswordInput.type = 'text'; // Tampilkan password yang digenerate secara default
    passwordToggleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
});

formPasswordInput.addEventListener('input', () => {
    checkPasswordStrength(formPasswordInput.value);
});

passwordLengthSlider.addEventListener('input', () => {
    passwordLengthValue.textContent = passwordLengthSlider.value;
    if (formPasswordInput.value) { // Jika ada password, update generator
        const generatedPass = generatePassword(
            parseInt(passwordLengthSlider.value),
            includeAZ.checked,
            include09.checked,
            includeSpecial.checked
        );
        formPasswordInput.value = generatedPass;
        checkPasswordStrength(generatedPass);
    }
});

includeAZ.addEventListener('change', () => { if (formPasswordInput.value) generatePasswordBtn.click(); });
include09.addEventListener('change', () => { if (formPasswordInput.value) generatePasswordBtn.click(); });
includeSpecial.addEventListener('change', () => { if (formPasswordInput.value) generatePasswordBtn.click(); });