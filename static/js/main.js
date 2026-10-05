document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const cipherSelect = document.getElementById('cipher-select');
  const cipherTag = document.getElementById('cipher-tag');

  // Key groups
  const keySimple = document.getElementById('key-simple');
  const keyAffine = document.getElementById('key-affine');
  const keyHill = document.getElementById('key-hill');
  const keySuper = document.getElementById('key-super');
  const keyEnigma = document.getElementById('key-enigma');
  const simpleKeyHelp = document.getElementById('simple-key-help');

  // Hill matrix switch
  const hillRadios = document.querySelectorAll('input[name="hill-size"]');
  const hill2x2 = document.getElementById('hill-matrix-2x2');
  const hill3x3 = document.getElementById('hill-matrix-3x3');

  // Text inputs & buttons
  const textInput = document.getElementById('text-input');
  const inputFormatSelect = document.getElementById('input-format-select');
  const btnEncryptText = document.getElementById('btn-encrypt-text');
  const btnDecryptText = document.getElementById('btn-decrypt-text');
  const btnSwapText = document.getElementById('btn-swap-text');
  const btnDownloadTxt = document.getElementById('btn-download-txt');

  // Outputs & Visuals
  const outputRaw = document.getElementById('output-raw');
  const outputB64 = document.getElementById('output-b64');
  const outputHex = document.getElementById('output-hex');
  const visualCard = document.getElementById('visual-card');
  const visualContent = document.getElementById('visual-content');
  const toast = document.getElementById('toast');

  // File Elements
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const fileDetails = document.getElementById('file-details');
  const detailFilename = document.getElementById('detail-filename');
  const detailFilesize = document.getElementById('detail-filesize');
  const btnRemoveFile = document.getElementById('btn-remove-file');
  const fileCipherSelect = document.getElementById('file-cipher-select');
  const fileSuperExtra = document.getElementById('file-super-extra');
  const fileKey = document.getElementById('file-key');
  const fileTKey = document.getElementById('file-tkey');
  const btnEncryptFile = document.getElementById('btn-encrypt-file');
  const btnDecryptFile = document.getElementById('btn-decrypt-file');
  const fileStatus = document.getElementById('file-status');

  let selectedFile = null;

  // --- Toast Notification Helper ---
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2500);
  }

  // --- Tab Navigation ---
  tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      tabBtns.forEach((b) => b.classList.remove('active'));
      tabContents.forEach((c) => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId).classList.add('active');
    });
  });

  // --- Cipher Selection Handler ---
  function updateCipherUI() {
    const cipher = cipherSelect.value;
    const optText = cipherSelect.options[cipherSelect.selectedIndex].text;
    cipherTag.textContent = optText.split('(')[0].trim().toUpperCase();

    // Hide all key groups
    keySimple.style.display = 'none';
    keyAffine.style.display = 'none';
    keyHill.style.display = 'none';
    keySuper.style.display = 'none';
    keyEnigma.style.display = 'none';
    visualCard.style.display = 'none';

    if (cipher === 'affine') {
      keyAffine.style.display = 'block';
    } else if (cipher === 'hill') {
      keyHill.style.display = 'block';
    } else if (cipher === 'super_encryption') {
      keySuper.style.display = 'block';
    } else if (cipher === 'enigma') {
      keyEnigma.style.display = 'block';
    } else {
      keySimple.style.display = 'block';
      if (cipher === 'playfair') {
        simpleKeyHelp.textContent = 'Kunci Playfair akan disusun ke dalam matriks 5x5 (huruf J digabung dengan I).';
      } else if (cipher === 'vigenere_extended') {
        simpleKeyHelp.textContent = 'Mendukung semua 256 karakter ASCII dan byte biner.';
      } else {
        simpleKeyHelp.textContent = 'Untuk 26 alfabet, karakter non-huruf akan diabaikan secara otomatis.';
      }
    }
  }

  cipherSelect.addEventListener('change', updateCipherUI);
  updateCipherUI();

  // --- Hill Matrix Radio Toggle ---
  hillRadios.forEach((radio) => {
    radio.addEventListener('change', (e) => {
      if (e.target.value === '2') {
        hill2x2.style.display = 'grid';
        hill3x3.style.display = 'none';
      } else {
        hill2x2.style.display = 'none';
        hill3x3.style.display = 'grid';
      }
    });
  });

  // --- Gather Request Payload for Text Mode ---
  function getCipherPayload(isEncrypt) {
    const cipher = cipherSelect.value;
    const text = textInput.value;
    const payload = {
      cipher: cipher,
    };

    if (isEncrypt) {
      payload.plaintext = text;
    } else {
      payload.ciphertext = text;
      payload.input_format = inputFormatSelect.value;
    }

    if (cipher === 'vigenere_standard' || cipher === 'vigenere_autokey' || cipher === 'vigenere_extended' || cipher === 'playfair') {
      payload.key = document.getElementById('input-key').value;
    } else if (cipher === 'affine') {
      payload.a = parseInt(document.getElementById('affine-a').value, 10);
      payload.b = parseInt(document.getElementById('affine-b').value, 10);
    } else if (cipher === 'hill') {
      const size = document.querySelector('input[name="hill-size"]:checked').value;
      if (size === '2') {
        payload.matrix = [
          [parseInt(document.getElementById('h2-00').value, 10), parseInt(document.getElementById('h2-01').value, 10)],
          [parseInt(document.getElementById('h2-10').value, 10), parseInt(document.getElementById('h2-11').value, 10)],
        ];
      } else {
        payload.matrix = [
          [parseInt(document.getElementById('h3-00').value, 10), parseInt(document.getElementById('h3-01').value, 10), parseInt(document.getElementById('h3-02').value, 10)],
          [parseInt(document.getElementById('h3-10').value, 10), parseInt(document.getElementById('h3-11').value, 10), parseInt(document.getElementById('h3-12').value, 10)],
          [parseInt(document.getElementById('h3-20').value, 10), parseInt(document.getElementById('h3-21').value, 10), parseInt(document.getElementById('h3-22').value, 10)],
        ];
      }
    } else if (cipher === 'super_encryption') {
      payload.key = document.getElementById('super-vkey').value;
      payload.transposition_key = document.getElementById('super-tkey').value;
    } else if (cipher === 'enigma') {
      payload.rotors = [
        document.getElementById('enigma-r1').value,
        document.getElementById('enigma-r2').value,
        document.getElementById('enigma-r3').value,
      ];
      payload.initial_positions = [
        document.getElementById('enigma-pos1').value || 'A',
        document.getElementById('enigma-pos2').value || 'A',
        document.getElementById('enigma-pos3').value || 'A',
      ];
      payload.reflector = document.getElementById('enigma-reflector').value;
      payload.plugboard = document.getElementById('enigma-plugboard').value;
    }

    return payload;
  }

  // --- Render Visual Extras (Playfair / Hill / Enigma) ---
  function renderVisuals(data) {
    visualCard.style.display = 'none';
    visualContent.innerHTML = '';

    if (data.matrix && data.cipher === 'playfair') {
      visualCard.style.display = 'block';
      document.getElementById('visual-title').textContent = 'Matriks Kunci Playfair (5x5):';
      let tableHtml = '<table class="playfair-table">';
      data.matrix.forEach((row) => {
        tableHtml += '<tr>';
        row.forEach((cell) => {
          tableHtml += `<td>${cell}</td>`;
        });
        tableHtml += '</tr>';
      });
      tableHtml += '</table>';
      visualContent.innerHTML = tableHtml;
    } else if (data.inv_matrix && data.cipher === 'hill') {
      visualCard.style.display = 'block';
      document.getElementById('visual-title').textContent = 'Matriks & Balikan Modulo 26 (Hill):';
      let html = `<p style="margin-bottom:8px;">Determinan: <strong>${data.det}</strong> (mod 26)</p>`;
      html += '<div style="display:flex; gap:20px; justify-content:center;">';
      html += '<div><strong>Matriks K (Kunci):</strong><table class="playfair-table">';
      data.matrix.forEach((row) => {
        html += '<tr>' + row.map((v) => `<td>${v}</td>`).join('') + '</tr>';
      });
      html += '</table></div>';
      html += '<div><strong>Matriks K⁻¹ (Balikan):</strong><table class="playfair-table">';
      data.inv_matrix.forEach((row) => {
        html += '<tr>' + row.map((v) => `<td>${v}</td>`).join('') + '</tr>';
      });
      html += '</table></div>';
      html += '</div>';
      visualContent.innerHTML = html;
    } else if (data.end_positions && data.cipher === 'enigma') {
      visualCard.style.display = 'block';
      document.getElementById('visual-title').textContent = 'Status Posisi Rotor Akhir (Enigma):';
      visualContent.innerHTML = `<p style="text-align:center; font-family:var(--font-mono); font-size:1.1rem; font-weight:700;">${data.end_positions.join(' - ')}</p>`;
    }
  }

  // --- Encrypt Text Action ---
  btnEncryptText.addEventListener('click', async () => {
    const payload = getCipherPayload(true);
    try {
      btnEncryptText.disabled = true;
      const res = await fetch('/api/encrypt/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        outputRaw.value = data.ciphertext;
        outputB64.value = data.base64;
        outputHex.value = data.hex;
        renderVisuals(data);
        showToast('Enkripsi teks berhasil!');
      } else {
        alert(`Error: ${data.message || 'Gagal mengenkripsi teks'}`);
      }
    } catch (err) {
      alert(`Terjadi kesalahan jaringan: ${err.message}`);
    } finally {
      btnEncryptText.disabled = false;
    }
  });

  // --- Decrypt Text Action ---
  btnDecryptText.addEventListener('click', async () => {
    const payload = getCipherPayload(false);
    try {
      btnDecryptText.disabled = true;
      const res = await fetch('/api/decrypt/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (res.ok && data.status === 'success') {
        outputRaw.value = data.decrypted;
        outputB64.value = '';
        outputHex.value = '';
        visualCard.style.display = 'none';
        showToast('Dekripsi teks berhasil!');
      } else {
        alert(`Error: ${data.message || 'Gagal mendekripsi teks'}`);
      }
    } catch (err) {
      alert(`Terjadi kesalahan jaringan: ${err.message}`);
    } finally {
      btnDecryptText.disabled = false;
    }
  });

  // --- Swap Text ---
  btnSwapText.addEventListener('click', () => {
    if (outputRaw.value) {
      textInput.value = outputRaw.value;
      showToast('Keluaran ditukar menjadi masukan!');
    }
  });

  // --- Copy Buttons ---
  document.querySelectorAll('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-copy');
      const targetElem = document.getElementById(targetId);
      if (targetElem && targetElem.value) {
        navigator.clipboard.writeText(targetElem.value);
        showToast('Teks berhasil disalin ke papan klip!');
      }
    });
  });

  // --- Download as .txt ---
  btnDownloadTxt.addEventListener('click', () => {
    if (!outputRaw.value) return;
    const blob = new Blob([outputRaw.value], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kripto_output_${cipherSelect.value}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('File .txt berhasil diunduh!');
  });

  // --- FILE MODE LOGIC ---
  fileCipherSelect.addEventListener('change', () => {
    if (fileCipherSelect.value === 'super_encryption') {
      fileSuperExtra.style.display = 'block';
    } else {
      fileSuperExtra.style.display = 'none';
    }
  });

  // Drop zone events
  dropZone.addEventListener('click', () => fileInput.click());

  ['dragenter', 'dragover'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function handleFileSelected(file) {
    selectedFile = file;
    detailFilename.textContent = file.name;
    detailFilesize.textContent = `${formatBytes(file.size)} — ${file.type || 'application/octet-stream'}`;
    dropZone.style.display = 'none';
    fileDetails.style.display = 'flex';
    fileStatus.style.display = 'none';
  }

  btnRemoveFile.addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    dropZone.style.display = 'block';
    fileDetails.style.display = 'none';
    fileStatus.style.display = 'none';
  });

  // File Encrypt Action
  btnEncryptFile.addEventListener('click', async () => {
    if (!selectedFile) {
      alert('Pilih berkas terlebih dahulu.');
      return;
    }
    const key = fileKey.value;
    if (!key) {
      alert('Kunci file tidak boleh kosong.');
      return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('cipher', fileCipherSelect.value);
    formData.append('key', key);
    if (fileCipherSelect.value === 'super_encryption') {
      formData.append('transposition_key', fileTKey.value);
    }

    try {
      btnEncryptFile.disabled = true;
      fileStatus.style.display = 'block';
      fileStatus.className = 'alert-box alert-success';
      fileStatus.textContent = 'Sedang mengenkripsi dan membungkus metadata file...';

      const res = await fetch('/api/encrypt/file', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.message || 'Gagal memproses file.');
      }

      const blob = await res.blob();
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `${selectedFile.name}.dat`;
      a.click();
      URL.revokeObjectURL(downloadUrl);

      fileStatus.className = 'alert-box alert-success';
      fileStatus.textContent = `Enkripsi berkas berhasil! Berkas terenkripsi otomatis diunduh sebagai: ${selectedFile.name}.dat`;
      showToast('Enkripsi berkas selesai!');
    } catch (err) {
      fileStatus.className = 'alert-box alert-error';
      fileStatus.textContent = `Error: ${err.message}`;
    } finally {
      btnEncryptFile.disabled = false;
    }
  });

  // File Decrypt Action
  btnDecryptFile.addEventListener('click', async () => {
    if (!selectedFile) {
      alert('Pilih berkas terenkripsi terlebih dahulu.');
      return;
    }
    const key = fileKey.value;
    if (!key) {
      alert('Kunci file tidak boleh kosong.');
      return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('cipher', fileCipherSelect.value);
    formData.append('key', key);
    if (fileCipherSelect.value === 'super_encryption') {
      formData.append('transposition_key', fileTKey.value);
    }

    try {
      btnDecryptFile.disabled = true;
      fileStatus.style.display = 'block';
      fileStatus.className = 'alert-box alert-success';
      fileStatus.textContent = 'Sedang mendekripsi dan memulihkan metadata file...';

      const res = await fetch('/api/decrypt/file', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errJson = await res.json();
        throw new Error(errJson.message || 'Gagal memproses file.');
      }

      // Extract filename from header
      let filename = 'restored_file';
      const disposition = res.headers.get('Content-Disposition');
      if (disposition && disposition.includes('filename=')) {
        const parts = disposition.split('filename=');
        if (parts.length > 1) {
          filename = parts[1].replace(/["']/g, '').trim();
        }
      }

      const blob = await res.blob();
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(downloadUrl);

      fileStatus.className = 'alert-box alert-success';
      fileStatus.textContent = `Dekripsi berkas berhasil! Berkas dipulihkan kembali ke format aslinya: ${filename}`;
      showToast('Dekripsi berkas selesai!');
    } catch (err) {
      fileStatus.className = 'alert-box alert-error';
      fileStatus.textContent = `Error: ${err.message}`;
    } finally {
      btnDecryptFile.disabled = false;
    }
  });
});
