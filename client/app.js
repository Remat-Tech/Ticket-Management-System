// ---- API configuration ----
// Pages served from a local host talk to the local API on the same host, so
// local testing never reaches production data.
const LOCAL_HOSTS = ['localhost', '127.0.0.1'];
const API_BASE = LOCAL_HOSTS.includes(window.location.hostname)
  ? `http://${window.location.hostname}:4000`
  : 'https://ticket-management-system-9ssy.onrender.com';

// Must match CODE_LENGTH in docket-server/utils/mfa.js.
const MFA_CODE_LENGTH = 6;

// Anything that came from the server or the user (subjects, names, emails,
// escalation reasons, audit details...) goes through this before being
// concatenated into an innerHTML string. Customers and self-sign-in
// visitors control those values, and they're rendered in the agent/admin
// consoles where a session token sits in storage.
function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}

document.addEventListener('DOMContentLoaded', function () {

  // Show only the pill for the current page (based on data-step); hide the rest
  var current = Number(document.body.dataset.step || 0);
  document.querySelectorAll('.step-pill').forEach(function (el) {
    var i = Number(el.dataset.step);
    var isCurrent = i === current;
    el.classList.toggle('active', isCurrent);
    el.classList.toggle('step-hidden', !isCurrent);
  });

  // Trigger entrance/float motion on the landing page's hero boxes
  var moEls = document.querySelectorAll('.mo');
  if (moEls.length) {
    moEls.forEach(function (el, i) {
      var delay = Number(el.dataset.delay || i * 120);
      setTimeout(function () { el.classList.add('mo-in'); }, delay);
    });
  }

  // Mints a PREFIX-2026-XXXXXX id, retrying against whatever record ids you pass in
  // so two tickets/agents/users minted in this browser can't collide. After 20 misses
  // (vanishingly unlikely with 900,000 possible suffixes) it falls back to a
  // Date.now()-derived suffix so this can never loop forever.
  function genUniqueId(prefix, existingIds) {
    for (var attempt = 0; attempt < 20; attempt++) {
      var id = prefix + '-2026-' + String(Math.floor(Math.random() * 900000) + 100000);
      if (existingIds.indexOf(id) === -1) return id;
    }
    return prefix + '-2026-' + String(Date.now()).slice(-6);
  }

  // ---- Session storage: agent/admin "keep me signed in" ----
  // Both login forms offer a "keep me signed in on this device" checkbox,
  // but everything used to go straight into localStorage regardless of
  // whether it was checked — localStorage persists indefinitely either way,
  // so the checkbox had no actual effect. Checked now means localStorage
  // (survives closing the browser, same as before); unchecked means
  // sessionStorage (cleared when the tab/browser closes, like an ordinary
  // login session). saveSession clears the *other* storage on write so a
  // stale copy can't linger there from an earlier sign-in made with the
  // opposite choice; readSession checks both so a session written either
  // way is still found.
  function saveSession(key, value, persist) {
    var raw = JSON.stringify(value);
    if (persist) {
      localStorage.setItem(key, raw);
      sessionStorage.removeItem(key);
    } else {
      sessionStorage.setItem(key, raw);
      localStorage.removeItem(key);
    }
  }

  function readSession(key) {
    var raw = localStorage.getItem(key) || sessionStorage.getItem(key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  function clearSession(key) {
    localStorage.removeItem(key);
    sessionStorage.removeItem(key);
  }

  // ---- Auth token plumbing ----
  // The backend's requireAuth() rejects any request with no
  // "Authorization: Bearer <token>" header. Every actor object
  // (docketUser/docketAgent/docketAdmin) now carries the signed session
  // `token` the backend returns on login/signup — currentActor() finds
  // whichever one is present (a given page only ever has one populated;
  // it redirects to its own login otherwise) and authHeaders() turns
  // that into a header object to merge into a fetch() call.
  function currentActor() {
    var agent = readSession('docketAgent');
    if (agent && agent.token) return agent;
    var admin = readSession('docketAdmin');
    if (admin && admin.token) return admin;
    var user = null;
    try { user = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { user = null; }
    if (user && user.token) return user;
    return null;
  }

  function authHeaders() {
    var actor = currentActor();
    return actor && actor.token ? { 'Authorization': 'Bearer ' + actor.token } : {};
  }

  // A 401 on a requireAuth()-protected call means the actor's token is
  // missing or expired (sessions last 12 hours — see AUTH_TOKEN_SECRET/
  // signToken on the backend), not that there's genuinely no data. Without
  // this, an expired token made tickets look like they'd vanished on
  // refresh — the portal/agent/admin queues all treated "the fetch failed"
  // the same as "there's nothing to show". Clears whichever session is
  // stale and sends the actor back to the right login page instead.
  function handleAuthExpired() {
    if (readSession('docketAgent')) { clearSession('docketAgent'); window.location.href = 'agent-login.html'; return true; }
    if (readSession('docketAdmin')) { clearSession('docketAdmin'); window.location.href = 'admin-login.html'; return true; }
    var hasUser = false;
    try { hasUser = !!JSON.parse(localStorage.getItem('docketUser')); } catch (e) { hasUser = false; }
    if (hasUser) { localStorage.removeItem('docketUser'); window.location.href = 'login.html'; return true; }
    return false;
  }

  // "Sign out all devices": POST /api/auth/sign-out-everywhere ends every
  // session for this account, this one included, so on success the local
  // session is cleared too and the person goes back to sign-in. `signOut`
  // is the page's own local sign-out (clear session + redirect).
  function wireSignOutEverywhere(buttonId, signOut) {
    var btn = document.getElementById(buttonId);
    if (!btn) return;
    btn.addEventListener('click', function () {
      if (!window.confirm('Sign out of Docket on every device, including this one?')) return;
      btn.disabled = true;
      fetch(API_BASE + '/api/auth/sign-out-everywhere', { method: 'POST', headers: authHeaders() })
        .then(function (response) {
          // A 401 means this session was already revoked — the outcome the
          // person asked for, so sign out locally either way.
          if (!response.ok && response.status !== 401) {
            return response.json().catch(function () { return {}; }).then(function (data) {
              throw new Error(data.error || 'Unable to sign out of other devices.');
            });
          }
          signOut();
        })
        .catch(function (err) {
          console.error('Sign out everywhere error:', err);
          btn.disabled = false;
          alert(err.message || 'Unable to sign out of other devices.');
        });
    });
  }

  // ---- Email MFA (every sign-in: customer, agent, admin) ----
  // The sign-in endpoints no longer return a token — they email a 6-digit
  // code and respond { mfaRequired, challengeId }. This opens a dialog to
  // collect the code and resolves with POST /api/auth/mfa/verify's response
  // ({ token, actor, record, returning }). It rejects with err.cancelled
  // when the person closes the dialog, or with a normal Error (message
  // ready to show) when the challenge is dead and they must sign in again.
  function postJson(path, body) {
    return fetch(API_BASE + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }

  function promptForMfaCode(challenge, email) {
    return new Promise(function (resolve, reject) {
      var overlay = document.createElement('div');
      overlay.className = 'mfa-overlay';
      overlay.innerHTML =
        '<div class="mfa-dialog" role="dialog" aria-modal="true" aria-labelledby="mfaTitle">' +
          '<h2 id="mfaTitle">Check your email</h2>' +
          '<p class="lead">We sent a ' + MFA_CODE_LENGTH + '-digit sign-in code to <strong></strong>. It expires in 10 minutes.</p>' +
          '<div class="field" id="f-mfaCode">' +
            '<label for="mfaCode">Sign-in code</label>' +
            '<input type="text" id="mfaCode" inputmode="numeric" autocomplete="one-time-code" maxlength="' + MFA_CODE_LENGTH + '" placeholder="••••••">' +
            '<div class="err" id="err-mfaCode"></div>' +
          '</div>' +
          '<button class="btn-amber" type="button" id="mfaVerify">Verify and sign in</button>' +
          '<div class="mfa-status" id="mfaStatus" aria-live="polite"></div>' +
          '<div class="mfa-actions">' +
            '<a href="#" id="mfaResend">Resend code</a>' +
            '<a href="#" id="mfaCancel">Cancel</a>' +
          '</div>' +
        '</div>';
      overlay.querySelector('.lead strong').textContent = email;
      document.body.appendChild(overlay);

      var input = overlay.querySelector('#mfaCode');
      var field = overlay.querySelector('#f-mfaCode');
      var errEl = overlay.querySelector('#err-mfaCode');
      var verifyBtn = overlay.querySelector('#mfaVerify');
      var resendLink = overlay.querySelector('#mfaResend');
      var statusEl = overlay.querySelector('#mfaStatus');
      var verifyLabel = verifyBtn.textContent;
      var cooldownTimer = null;
      input.focus();

      function close() {
        if (cooldownTimer) clearInterval(cooldownTimer);
        document.removeEventListener('keydown', onKeydown);
        overlay.remove();
      }
      function showError(message) {
        errEl.textContent = message;
        field.classList.add('invalid');
      }
      function fail(message) {
        close();
        reject(new Error(message));
      }
      function startResendCooldown(seconds) {
        var left = seconds;
        resendLink.setAttribute('aria-disabled', 'true');
        resendLink.textContent = 'Resend code (' + left + 's)';
        if (cooldownTimer) clearInterval(cooldownTimer);
        cooldownTimer = setInterval(function () {
          left -= 1;
          if (left <= 0) {
            clearInterval(cooldownTimer);
            cooldownTimer = null;
            resendLink.removeAttribute('aria-disabled');
            resendLink.textContent = 'Resend code';
          } else {
            resendLink.textContent = 'Resend code (' + left + 's)';
          }
        }, 1000);
      }
      startResendCooldown(60);

      function verify() {
        if (verifyBtn.disabled) return; // already checking (auto-submit + Enter)
        var code = input.value.replace(/\D/g, '');
        if (code.length !== MFA_CODE_LENGTH) { showError('Enter the ' + MFA_CODE_LENGTH + '-digit code from your email.'); return; }
        field.classList.remove('invalid');
        verifyBtn.disabled = true;
        verifyBtn.textContent = 'Verifying…';

        postJson('/api/auth/mfa/verify', { challengeId: challenge.challengeId, code: code })
          .then(function (res) {
            if (res.ok) { close(); resolve(res.data); return; }
            if (res.data.restart) { fail(res.data.error || 'Please sign in again.'); return; }
            var message = res.data.error || 'Unable to verify the code.';
            if (res.data.attemptsRemaining) {
              message += ' ' + res.data.attemptsRemaining + ' attempt' + (res.data.attemptsRemaining === 1 ? '' : 's') + ' left.';
            }
            showError(message);
            input.select();
          })
          .catch(function () { showError('Network error. Please try again.'); })
          .finally(function () {
            verifyBtn.disabled = false;
            verifyBtn.textContent = verifyLabel;
          });
      }

      function onKeydown(e) {
        if (e.key === 'Escape') { e.preventDefault(); cancel(); }
      }
      function cancel() {
        close();
        var err = new Error('Sign-in cancelled.');
        err.cancelled = true;
        reject(err);
      }

      input.addEventListener('input', function () {
        input.value = input.value.replace(/\D/g, '').slice(0, MFA_CODE_LENGTH);
        if (input.value.length === MFA_CODE_LENGTH) verify();
      });
      input.addEventListener('keydown', function (e) { if (e.key === 'Enter') verify(); });
      verifyBtn.addEventListener('click', verify);
      document.addEventListener('keydown', onKeydown);
      overlay.querySelector('#mfaCancel').addEventListener('click', function (e) { e.preventDefault(); cancel(); });

      resendLink.addEventListener('click', function (e) {
        e.preventDefault();
        if (resendLink.getAttribute('aria-disabled') === 'true') return;
        resendLink.setAttribute('aria-disabled', 'true');
        statusEl.textContent = 'Sending a new code…';
        postJson('/api/auth/mfa/resend', { challengeId: challenge.challengeId })
          .then(function (res) {
            if (res.ok) {
              statusEl.textContent = 'New code sent. The previous code no longer works.';
              input.value = '';
              input.focus();
              startResendCooldown(60);
              return;
            }
            if (res.data.restart) { fail(res.data.error || 'Please sign in again.'); return; }
            statusEl.textContent = res.data.error || 'Unable to resend the code.';
            startResendCooldown(res.data.retryAfterSeconds || 10);
          })
          .catch(function () {
            statusEl.textContent = 'Network error. Please try again.';
            resendLink.removeAttribute('aria-disabled');
          });
      });
    });
  }

  // ---- Real file uploads (phase 1D-vi) ----
  // Attachments used to be filenames-only — chosen in the browser, never
  // actually read or sent anywhere, so there was nothing to open or
  // download later. Files are now read as base64 client-side and POSTed
  // as part of ticket creation / chat comments; the server stores the
  // bytes in `ticket_attachments` and serves them back from
  // GET /api/attachments/:id. Kept small (base64 in a JSON body, not a
  // real multipart upload) to match the rest of this app's SQLite-only,
  // no-object-storage architecture — fine for the file sizes a support
  // ticket realistically carries, not meant for large uploads.
  var MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5MB per file — matches the server-side cap

  // Reads a single File into the shape the API expects:
  // { filename, content_base64, mime_type, size_bytes }. Rejects anything
  // over the cap before ever touching the network.
  function readFileAsAttachment(file) {
    return new Promise(function (resolve, reject) {
      if (file.size > MAX_ATTACHMENT_BYTES) {
        reject(new Error('"' + file.name + '" is larger than 5MB — attachments are capped at 5MB each.'));
        return;
      }
      var reader = new FileReader();
      reader.onload = function () {
        // reader.result is a data URL ("data:<mime>;base64,<data>") —
        // only the part after the comma is the actual payload.
        var raw = String(reader.result);
        var content = raw.slice(raw.indexOf(',') + 1);
        resolve({
          filename: file.name,
          content_base64: content,
          mime_type: file.type || 'application/octet-stream',
          size_bytes: file.size
        });
      };
      reader.onerror = function () { reject(new Error('Unable to read "' + file.name + '".')); };
      reader.readAsDataURL(file);
    });
  }

  // GET /api/attachments/:id requires an Authorization header, which a
  // plain <a href> navigation can't send — so a chip with a real id
  // fetches the bytes itself (with the current actor's token) and hands
  // the browser a local blob: URL to save, instead of linking straight
  // at the API.
  function downloadAttachment(id, filename) {
    fetch(API_BASE + '/api/attachments/' + encodeURIComponent(id), { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) throw new Error('Unable to download this file.');
        return response.blob();
      })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename || 'download';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      })
      .catch(function (err) {
        console.error('Attachment download error:', err);
        alert(err.message || 'Unable to download this file.');
      });
  }

  // Opens an attachment in an in-page preview window instead of forcing a
  // download. Same auth-header fetch as downloadAttachment, then the blob is
  // shown according to what it is (picked from the filename's extension,
  // falling back to the stored mime type):
  //   - images, PDFs, audio, video -> rendered from a blob: URL
  //   - plain-text formats         -> read and shown as text (textContent,
  //     so an uploaded .html/.js is displayed, never run)
  //   - anything else              -> "no preview" plus the download button
  // A blob: URL inherits this page's origin, so the blob is always re-typed
  // to the format we decided on rather than trusting the uploader's
  // mime_type — a file claiming text/html must never be loaded into a frame.
  var PREVIEW_TYPES = {
    image: { exts: ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'], mime: /^image\// },
    pdf: { exts: ['pdf'], mime: /^application\/pdf$/ },
    video: { exts: ['mp4', 'webm', 'mov'], mime: /^video\// },
    audio: { exts: ['mp3', 'wav', 'ogg', 'm4a'], mime: /^audio\// },
    text: { exts: ['txt', 'log', 'csv', 'json', 'md', 'xml', 'yml', 'yaml', 'ini', 'html', 'htm', 'js', 'css', 'sql'], mime: /^text\/|^application\/json$/ }
  };
  var IMAGE_MIME_BY_EXT = { jpg: 'image/jpeg', jpeg: 'image/jpeg', svg: 'image/svg+xml' };

  function previewKindFor(filename, mime) {
    var ext = String(filename || '').toLowerCase().split('.').pop();
    var kinds = Object.keys(PREVIEW_TYPES);
    for (var i = 0; i < kinds.length; i++) {
      if (PREVIEW_TYPES[kinds[i]].exts.indexOf(ext) !== -1) return { kind: kinds[i], ext: ext };
    }
    for (var j = 0; j < kinds.length; j++) {
      if (PREVIEW_TYPES[kinds[j]].mime.test(mime || '')) return { kind: kinds[j], ext: ext };
    }
    return { kind: null, ext: ext };
  }

  function previewAttachment(id, filename) {
    var objectUrl = null;
    var overlay = document.createElement('div');
    overlay.className = 'attachment-preview-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.innerHTML =
      '<div class="attachment-preview-dialog">' +
        '<div class="attachment-preview-header">' +
          '<span class="attachment-preview-title"></span>' +
          '<div class="attachment-preview-actions">' +
            '<button class="btn-ghost btn-inline" type="button" data-preview-download>Download</button>' +
            '<button class="attachment-preview-close" type="button" aria-label="Close preview">×</button>' +
          '</div>' +
        '</div>' +
        '<div class="attachment-preview-body"><p class="attachment-preview-note">Loading preview…</p></div>' +
      '</div>';
    overlay.querySelector('.attachment-preview-title').textContent = '📎 ' + (filename || 'Attachment');
    var body = overlay.querySelector('.attachment-preview-body');

    function close() {
      document.removeEventListener('keydown', onKey);
      overlay.remove();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    }
    function onKey(e) { if (e.key === 'Escape') close(); }
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    overlay.querySelector('.attachment-preview-close').addEventListener('click', close);
    overlay.querySelector('[data-preview-download]').addEventListener('click', function () {
      downloadAttachment(id, filename);
    });
    document.addEventListener('keydown', onKey);
    document.body.appendChild(overlay);
    overlay.querySelector('.attachment-preview-close').focus();

    function showNote(text) {
      body.innerHTML = '';
      var p = document.createElement('p');
      p.className = 'attachment-preview-note';
      p.textContent = text;
      body.appendChild(p);
    }

    fetch(API_BASE + '/api/attachments/' + encodeURIComponent(id), { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) throw new Error('Unable to load this file.');
        return response.blob();
      })
      .then(function (blob) {
        if (!document.body.contains(overlay)) return; // closed while loading
        var detected = previewKindFor(filename, blob.type);
        var el;
        if (detected.kind === 'text') {
          return blob.text().then(function (text) {
            body.innerHTML = '';
            var pre = document.createElement('pre');
            pre.className = 'attachment-preview-text';
            pre.textContent = text;
            body.appendChild(pre);
          });
        }
        if (detected.kind === 'image') {
          var imageMime = IMAGE_MIME_BY_EXT[detected.ext] ||
            (/^image\//.test(blob.type) ? blob.type : 'image/' + detected.ext);
          objectUrl = URL.createObjectURL(new Blob([blob], { type: imageMime }));
          el = document.createElement('img');
          el.alt = filename || 'Attachment preview';
        } else if (detected.kind === 'pdf') {
          objectUrl = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
          el = document.createElement('iframe');
          el.title = filename || 'Attachment preview';
        } else if (detected.kind === 'video' || detected.kind === 'audio') {
          objectUrl = URL.createObjectURL(blob);
          el = document.createElement(detected.kind);
          el.controls = true;
        } else {
          showNote('No preview is available for this file type. Use Download to open it.');
          return;
        }
        el.className = 'attachment-preview-media attachment-preview-' + detected.kind;
        el.src = objectUrl;
        body.innerHTML = '';
        body.appendChild(el);
      })
      .catch(function (err) {
        console.error('Attachment preview error:', err);
        showNote(err.message || 'Unable to load this file.');
      });
  }

  // Same "fetch with auth header, hand the browser a blob: URL" trick as
  // downloadAttachment, generalized for the admin console's report exports
  // — the server names the file via Content-Disposition, but that's only
  // reachable from JS, never from a plain <a href>, since a real download
  // link would carry no Authorization header at all.
  function downloadReportFile(url, fallbackFilename) {
    return fetch(url, { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) {
          return response.json().catch(function () { return {}; }).then(function (data) {
            throw new Error(data.error || 'Unable to generate this report.');
          });
        }
        var disposition = response.headers.get('Content-Disposition') || '';
        var match = /filename="([^"]+)"/.exec(disposition);
        var filename = match ? match[1] : fallbackFilename;
        return response.blob().then(function (blob) { return { blob: blob, filename: filename }; });
      })
      .then(function (result) {
        var objectUrl = URL.createObjectURL(result.blob);
        var a = document.createElement('a');
        a.href = objectUrl;
        a.download = result.filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(function () { URL.revokeObjectURL(objectUrl); }, 1000);
      });
  }

  // Renders a row of "📎 filename" chips for the attachments a ticket/comment
  // carries. Each entry is either a real attachment ({ id, filename }, once
  // it has an id it can be downloaded from GET /api/attachments/:id) or —
  // for anything written before this feature existed — a bare filename
  // string with nothing to link to. No-op if the container isn't on this
  // page, or there's nothing to show.
  function renderAttachmentChips(container, items) {
    if (!container) return;
    container.innerHTML = '';
    (items || []).forEach(function (item) {
      var isObj = item && typeof item === 'object';
      var name = isObj ? item.filename : item;
      var id = isObj ? item.id : null;
      var chip = id != null ? document.createElement('a') : document.createElement('span');
      chip.className = 'chat-attachment-chip';
      if (id != null) {
        chip.href = '#';
        chip.addEventListener('click', function (e) {
          e.preventDefault();
          previewAttachment(id, name);
        });
      }
      chip.textContent = '📎 ' + name;
      container.appendChild(chip);
    });
  }

  // Stores a customer's POST /api/auth/mfa/verify response as the
  // `docketUser` session (shared by sign-up and sign-in). Normalizes the
  // API's `full_name` into the `name` field the rest of app.js (ticket
  // creation, portal, chat) already reads. The server record is the source
  // of truth; this is just a session cache.
  function saveUserSession(verified) {
    var data = verified.record;
    var user = {
      id: data.id,
      name: data.full_name,
      email: data.email,
      phone: data.phone,
      department: data.department,
      organization: data.organization,
      token: verified.token
    };
    localStorage.setItem('docketUser', JSON.stringify(user));
    return user;
  }

  // ---- Customer sign-in (login.html): email -> emailed code -> portal ----
  var signInForm = document.getElementById('signInForm');
  if (signInForm) {
    var signedInUser = null;
    try { signedInUser = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { signedInUser = null; }
    if (signedInUser && signedInUser.token) {
      window.location.replace('portal.html');
      return;
    }

    var signInEmail = document.getElementById('signInEmail');
    var signInField = document.getElementById('f-signInEmail');
    var signInErr = document.getElementById('err-signInEmail');
    var submitSignInBtn = document.getElementById('submitSignIn');
    var submitSignInDefaultLabel = submitSignInBtn.textContent;

    function showSignInError(message) {
      signInErr.textContent = message;
      signInField.classList.add('invalid');
    }

    function submitSignIn() {
      if (submitSignInBtn.disabled) return;
      var email = signInEmail.value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showSignInError('Enter a valid email address.');
        return;
      }
      signInField.classList.remove('invalid');
      submitSignInBtn.disabled = true;
      submitSignInBtn.textContent = 'Sending code…';

      postJson('/api/users/sign-in', { email: email })
        .then(function (res) {
          if (res.ok) return promptForMfaCode(res.data, email);
          if (res.data.signup) {
            // Point at "Find my account" before "Create an account", so someone
            // who's sure they've signed up before doesn't make a duplicate.
            signInErr.innerHTML = '';
            signInErr.appendChild(document.createTextNode((res.data.error || 'No account found.') + ' '));
            var helpLink = document.createElement('a');
            helpLink.href = '#';
            helpLink.className = 'account-help-link';
            helpLink.textContent = 'Find my account';
            helpLink.addEventListener('click', openAccountHelp);
            signInErr.appendChild(helpLink);
            signInErr.appendChild(document.createTextNode(' or '));
            var link = document.createElement('a');
            link.href = 'profile.html';
            link.textContent = 'create a new account';
            signInErr.appendChild(link);
            signInErr.appendChild(document.createTextNode('.'));
            signInField.classList.add('invalid');
            return null;
          }
          throw new Error(res.data.error || 'Unable to sign in.');
        })
        .then(function (verified) {
          if (!verified) return;
          saveUserSession(verified);
          window.location.href = 'portal.html';
        })
        .catch(function (err) {
          if (err.cancelled) return;
          console.error('Sign-in error:', err);
          showSignInError(err.message || 'Something went wrong. Please try again.');
        })
        .finally(function () {
          submitSignInBtn.disabled = false;
          submitSignInBtn.textContent = submitSignInDefaultLabel;
        });
    }

    submitSignInBtn.addEventListener('click', submitSignIn);
    signInEmail.addEventListener('keydown', function (e) { if (e.key === 'Enter') submitSignIn(); });

    // ---- "Find my account" (POST /api/account-help) ----
    // For customers who can't remember which email they signed up with. The
    // server answers the same way whether or not anything matches, and an
    // admin follows up from the Account Help tab.
    var accountHelpForm = document.getElementById('accountHelpForm');
    var accountHelpDone = document.getElementById('accountHelpDone');

    function showSignInCard(which) {
      signInForm.style.display = which === 'signin' ? '' : 'none';
      accountHelpForm.style.display = which === 'help' ? '' : 'none';
      accountHelpDone.style.display = which === 'done' ? '' : 'none';
    }

    function openAccountHelp(e) {
      if (e) e.preventDefault();
      showSignInCard('help');
      document.getElementById('helpName').focus();
    }

    function backToSignIn(e) {
      if (e) e.preventDefault();
      showSignInCard('signin');
      signInEmail.focus();
    }

    document.querySelectorAll('.account-help-link').forEach(function (a) { a.addEventListener('click', openAccountHelp); });
    document.getElementById('backToSignIn').addEventListener('click', backToSignIn);
    document.getElementById('doneBackToSignIn').addEventListener('click', backToSignIn);

    var submitAccountHelpBtn = document.getElementById('submitAccountHelp');
    var accountHelpSubmitErr = document.getElementById('err-helpSubmit');

    function submitAccountHelp() {
      if (submitAccountHelpBtn.disabled) return;
      var nameEl = document.getElementById('helpName');
      var emailEl = document.getElementById('helpEmail');
      var nameOk = !!nameEl.value.trim();
      var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailEl.value.trim());
      document.getElementById('f-helpName').classList.toggle('invalid', !nameOk);
      document.getElementById('f-helpEmail').classList.toggle('invalid', !emailOk);
      accountHelpSubmitErr.style.display = 'none';
      if (!nameOk || !emailOk) return;

      submitAccountHelpBtn.disabled = true;
      submitAccountHelpBtn.textContent = 'Sending…';

      postJson('/api/account-help', {
        full_name: nameEl.value.trim(),
        contact_email: emailEl.value.trim(),
        phone: document.getElementById('helpPhone').value.trim(),
        organization: document.getElementById('helpOrganization').value.trim(),
        details: document.getElementById('helpDetails').value.trim(),
        website: document.getElementById('helpWebsite').value
      })
        .then(function (res) {
          if (!res.ok) throw new Error(res.data.error || 'Unable to send your request.');
          document.getElementById('accountHelpDoneText').textContent = res.data.message;
          showSignInCard('done');
        })
        .catch(function (err) {
          accountHelpSubmitErr.textContent = err.message && err.message !== 'Failed to fetch' ? err.message : 'Network error. Please try again.';
          accountHelpSubmitErr.style.display = 'block';
        })
        .finally(function () {
          submitAccountHelpBtn.disabled = false;
          submitAccountHelpBtn.textContent = 'Send request';
        });
    }

    submitAccountHelpBtn.addEventListener('click', submitAccountHelp);
  }

  // Profile form validation + confirmation stub
  var profileForm = document.getElementById('profileForm');
  if (profileForm) {

    // Returning-user check: if a profile already exists on this device, show it
    // straight away instead of minting a brand-new USR id every time someone
    // passes through login -> profile.
    function showProfileStub(user, isReturning) {
      document.getElementById('stubId').textContent = user.id;
      document.getElementById('stubName').textContent = ', ' + user.name.trim().split(' ')[0];
      document.getElementById('stubLead').textContent = isReturning
        ? 'Welcome back — we found a saved profile on this device.'
        : 'Your details are saved.';
      profileForm.style.display = 'none';
      document.getElementById('stub').classList.add('show');
      var notYouLink = document.getElementById('notYouLink');
      notYouLink.style.display = isReturning ? 'block' : 'none';
      var stubCta = document.getElementById('stubCta');
      stubCta.href = 'portal.html';
      stubCta.textContent = 'Go to my portal →';
    }

    var existingUser = null;
    try { existingUser = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { existingUser = null; }
    if (existingUser && existingUser.id && existingUser.name) {
      showProfileStub(existingUser, true);
    }

    document.getElementById('notYouLink').addEventListener('click', function (e) {
      e.preventDefault();
      localStorage.removeItem('docketUser');
      document.getElementById('notYouLink').style.display = 'none';
      document.getElementById('stub').classList.remove('show');
      profileForm.style.display = '';
      document.getElementById('fullName').value = '';
      document.getElementById('email').value = '';
      document.getElementById('phone').value = '';
      document.getElementById('dept').value = '';
      document.getElementById('org').value = '';
    });

    var submitProfileBtn = document.getElementById('submitProfile');
    var submitProfileDefaultLabel = submitProfileBtn ? submitProfileBtn.textContent : '';

    // Surfaces a submission-time error near the email field (reusing the
    // f-email/err-email pattern used elsewhere, e.g. admin-login), falling
    // back to alert() if this page doesn't have an err-email element.
    function showProfileError(message) {
      var emailWrap = document.getElementById('f-email');
      var emailErr = document.getElementById('err-email');
      if (emailWrap) emailWrap.classList.add('invalid');
      if (emailErr) {
        emailErr.textContent = message;
      } else {
        alert(message);
      }
    }

    submitProfileBtn.addEventListener('click', function () {
      var name = document.getElementById('fullName');
      var email = document.getElementById('email');
      var phone = document.getElementById('phone');
      var dept = document.getElementById('dept');
      var org = document.getElementById('org');
      var valid = true;

      if (!name.value.trim()) {
        document.getElementById('f-name').classList.add('invalid');
        valid = false;
      } else {
        document.getElementById('f-name').classList.remove('invalid');
      }

      var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim());
      if (!emailOk) {
        document.getElementById('f-email').classList.add('invalid');
        valid = false;
      } else {
        document.getElementById('f-email').classList.remove('invalid');
      }

      if (!valid) return;

      submitProfileBtn.disabled = true;
      submitProfileBtn.textContent = 'Saving…';

      fetch(API_BASE + '/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: name.value.trim(),
          email: email.value.trim(),
          phone: phone && phone.value.trim() ? phone.value.trim() : null,
          department: dept && dept.value.trim() ? dept.value.trim() : null,
          organization: org && org.value.trim() ? org.value.trim() : null
        })
      })
        .then(function (response) {
          return response.json().then(function (data) {
            if (!response.ok) throw new Error(data.error || 'Unable to save your profile.');
            return data;
          });
        })
        .then(function (challenge) {
          return promptForMfaCode(challenge, email.value.trim());
        })
        .then(function (verified) {
          var newUser = saveUserSession(verified);
          document.getElementById('f-email').classList.remove('invalid');
          showProfileStub(newUser, verified.returning === true);
        })
        .catch(function (err) {
          if (err.cancelled) return;
          console.error('Profile creation error:', err);
          showProfileError(err.message || 'Something went wrong. Please try again.');
        })
        .finally(function () {
          submitProfileBtn.disabled = false;
          submitProfileBtn.textContent = submitProfileDefaultLabel;
        });
    });
  }

  // ---- Agent directory: shared by agent sign-in, the agent dashboard's reassign
  // panel, and the admin console. Now backed by GET /api/agents on Render/SQLite —
  // the seeded five agents (Maya Owusu, Kwame Boateng, Ama Serwaa, Yaw Mensah, Efia
  // Asante) already live there via db/seed.js, so the client no longer seeds or
  // mints AGT ids itself.
  //
  // loadAgents() stays a *synchronous* read of a local cache — every existing call
  // site (reassign dropdown, admin assign dropdown, admin directory tab, stats
  // counts) reads it that way, several of them on every 4s poll tick. Hitting the
  // network that often would be wasteful, so refreshAgentDirectory() is what
  // actually talks to the API; call it once when a page needs the directory, then
  // read loadAgents() afterward. It's safe to call again any time (e.g. after
  // adding an agent) to pick up the latest list.
  var agentDirectoryCache = [];

  function loadAgents() {
    return agentDirectoryCache;
  }

  function normalizeAgent(a) {
    return { id: a.id, name: a.full_name, email: a.email, createdAt: a.created_at, createdBy: a.created_by };
  }

  function refreshAgentDirectory(onDone, onError) {
    fetch(API_BASE + '/api/agents', { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) throw new Error('Unable to load the agent directory.');
        return response.json();
      })
      .then(function (agents) {
        agentDirectoryCache = agents.map(normalizeAgent);
        if (onDone) onDone(agentDirectoryCache);
      })
      .catch(function (err) {
        console.error('Agent directory load error:', err);
        if (onError) onError(err);
      });
  }

  // ---- Ticket data access (phase 1D-i) ----
  // Tickets now come from the API instead of the `docketTickets` localStorage
  // array. Server rows are snake_case and reference the requester/assignee by
  // id, while every render function in this file was written against the old
  // client-side shape — normalizeTicket() bridges the two, so nothing
  // downstream of it needed rewriting.
  //
  // Two things the API doesn't return yet, each noted at its use site below:
  //   - creation-time attachment filenames (only attachment_count comes back)
  //   - who escalated / who resolved (only the target and the text)
  // The requester's email now comes back on the ticket row itself
  // (requester_email, via tickets.js's LEFT JOIN to users) so there's no
  // need to fetch the whole users table just to reconstruct it client-side.

  // normalizeTicket() reads the agent cache, so it has to be warm before any
  // ticket is mapped. A failed directory load is non-fatal — tickets still
  // render, just with an id where a name would be — so the callback still runs.
  function withDirectories(onReady) {
    refreshAgentDirectory(onReady, onReady);
  }

  function agentNameForId(id) {
    if (!id) return null;
    var match = loadAgents().filter(function (a) { return a.id === id; })[0];
    return match ? match.name : id;
  }

  function normalizeTicket(row) {
    return {
      id: row.id,
      subject: row.subject,
      description: row.description,
      category: row.category,
      priority: row.priority,
      service: row.affected_service || '',
      team: row.assigned_team,
      sla: row.sla_summary,
      files: row.attachment_count || 0,
      // Only the count comes back from the API, not the filenames, so the
      // attachment *chips* stay hidden even when the count is non-zero. The
      // `Array.isArray` check means they light up on their own if tickets.js
      // later starts returning an `attachments` array.
      attachments: Array.isArray(row.attachments) ? row.attachments : [],
      userId: row.user_id,
      email: row.requester_email || row.user_id,
      status: row.status,
      assignedAgentId: row.assigned_agent_id || null,
      assignedAgent: agentNameForId(row.assigned_agent_id),
      suggestedAgentId: row.suggested_agent_id || null,
      suggestedAgent: agentNameForId(row.suggested_agent_id),
      createdAt: row.created_at,
      // `by` is blank because the API records what was written, not who wrote
      // it; the render sites below omit the attribution when it's empty.
      resolutionSummary: row.resolution_summary ? { text: row.resolution_summary, by: '' } : null,
      escalation: row.escalated_to ? { to: row.escalated_to, reason: row.escalation_reason || '', by: '' } : null,
      csat: row.csat_rating != null ? { score: row.csat_rating, comment: row.csat_comment || '' } : null,
      // SLA clock — the server sets these; see docket-server/utils/sla.js.
      resolutionDueAt: row.resolution_due_at || null,
      resolvedAt: row.resolved_at || null,
      slaPausedAt: row.sla_paused_at || null,
      // Sent back with assign/status updates so the server can refuse one
      // based on a stale copy (see rejectStaleTicket in routes/tickets.js).
      version: row.version
    };
  }

  // What the agent/admin queue polls compare to decide whether a ticket
  // changed enough to re-render. The version keeps each ticket's copy current
  // even for changes that leave status and assignee alone.
  function ticketSignature(t) {
    return t.status + '|' + (t.assignedAgent || '') + '|' + t.version;
  }

  // Reads a ticket update response. A 409 means the ticket changed since it
  // was loaded: the error carries the server's current copy as `latest` so the
  // caller can show it in place of the stale one.
  function readTicketUpdate(response, fallbackMessage) {
    return response.json().then(function (data) {
      if (response.status === 409) {
        var conflict = new Error(data.error || 'This ticket has changed.');
        if (data.ticket) conflict.latest = normalizeTicket(data.ticket);
        throw conflict;
      }
      if (!response.ok) throw new Error(data.error || fallbackMessage);
      return data;
    });
  }

  // ---- SLA tracking ----
  // The server stores absolute due times and pauses/resumes the resolution
  // clock (docket-server/utils/sla.js); this only compares them to the
  // current time. The clock comes back as one of:
  //   met | breached   — final outcome
  //   pending          — running, plenty of time left
  //   due-soon         — running, under a quarter of the window left
  //   paused           — waiting on the customer
  // or null for a ticket with no SLA data.
  var SLA_DUE_SOON_FRACTION = 0.25;

  function slaTime(v) { return v ? new Date(v).getTime() : null; }

  function runningClock(due, start, now) {
    if (now > due) return 'breached';
    return (due - now) < (due - start) * SLA_DUE_SOON_FRACTION ? 'due-soon' : 'pending';
  }

  function slaInfo(t, now) {
    now = now || Date.now();
    var created = slaTime(t.createdAt);
    var resolutionDue = slaTime(t.resolutionDueAt);
    var info = { resolution: null, resolutionDue: null };

    if (resolutionDue) {
      var resolved = slaTime(t.resolvedAt);
      var paused = slaTime(t.slaPausedAt);
      // While paused, the due time slides forward with the clock, so the
      // ticket can't breach while it's waiting on the customer.
      var effectiveDue = paused ? resolutionDue + (now - paused) : resolutionDue;
      info.resolutionDue = effectiveDue;
      if (resolved && (t.status === 'Resolved' || t.status === 'Closed')) {
        info.resolution = resolved <= resolutionDue ? 'met' : 'breached';
      } else if (now > effectiveDue) {
        info.resolution = 'breached';
      } else {
        info.resolution = paused ? 'paused' : runningClock(effectiveDue, created, now);
      }
    }
    return info;
  }

  // "in 2h 5m" / "3d 4h ago" relative to now.
  function fmtSlaRelative(ms, now) {
    var diff = ms - now;
    var mins = Math.round(Math.abs(diff) / 60000);
    var text;
    if (mins < 60) text = mins + 'm';
    else if (mins < 24 * 60) text = Math.floor(mins / 60) + 'h ' + (mins % 60) + 'm';
    else text = Math.floor(mins / 1440) + 'd ' + Math.floor((mins % 1440) / 60) + 'h';
    return diff >= 0 ? 'in ' + text : text + ' ago';
  }

  // The single most urgent SLA warning for an open ticket, for its queue
  // row and the "SLA breached" stat: { level: 'breached'|'due-soon', text },
  // or null when nothing needs attention.
  function slaAlert(t, now) {
    if (t.status === 'Resolved' || t.status === 'Closed') return null;
    now = now || Date.now();
    var s = slaInfo(t, now);
    if (s.resolution === 'breached') return { level: 'breached', text: 'SLA breached' };
    if (s.resolution === 'due-soon') return { level: 'due-soon', text: 'Due ' + fmtSlaRelative(s.resolutionDue, now) };
    return null;
  }

  function slaAlertChipHtml(t, now) {
    var alertInfo = slaAlert(t, now);
    if (!alertInfo) return '';
    return '<span class="history-chip sla-chip sla-' + alertInfo.level + '">' + escapeHtml(alertInfo.text) + '</span>';
  }

  // Fills a ticket detail's SLA box: the target, then the clock's state.
  function renderSlaBox(el, t) {
    if (!el) return;
    var now = Date.now();
    var s = slaInfo(t, now);
    if (!s.resolution) { el.textContent = t.sla || '—'; return; }

    function line(label, state, due) {
      var text;
      if (state === 'met') text = 'met';
      else if (state === 'breached') text = 'breached' + (due && t.status !== 'Resolved' && t.status !== 'Closed' ? ' (due ' + fmtSlaRelative(due, now) + ')' : '');
      else if (state === 'paused') text = 'paused, waiting on customer';
      else text = 'due ' + fmtSlaRelative(due, now);
      return '<span class="sla-line sla-' + (state || 'pending') + '">' + label + ': ' + escapeHtml(text) + '</span>';
    }

    el.innerHTML =
      '<span class="sla-targets">' + escapeHtml(t.sla || '') + '</span>' +
      line('Resolution', s.resolution, s.resolutionDue);
  }

  // PATCH /api/tickets/:id/assign — pass a falsy agentId to send the ticket
  // back to the pool. The server owns the status side-effects here (claiming a
  // Created ticket makes it Assigned; unassigning anything that isn't
  // Resolved/Closed drops it back to Created), so the handlers below no longer
  // repeat that logic client-side — they render whatever comes back.
  function assignTicket(t, agentId, onDone, onError) {
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(t.id) + '/assign', {
      method: 'PATCH',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ assigned_agent_id: agentId || null, version: t.version })
    })
      .then(function (response) { return readTicketUpdate(response, 'Unable to update the assignment.'); })
      .then(function (row) { onDone(normalizeTicket(row)); })
      .catch(function (err) {
        console.error('Assign error:', err);
        if (onError) onError(err);
      });
  }

  // PATCH /api/tickets/:id/status — body is whatever tickets.js's /status
  // route expects for the move being made: { status } for a plain transition,
  // plus resolution_summary for Resolved or escalated_to/escalation_reason
  // for Escalated. Same shape as assignTicket(): the server is the source of
  // truth for the resulting row, so callers render whatever comes back
  // instead of trusting their own local mutation.
  function changeTicketStatus(t, body, onDone, onError) {
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(t.id) + '/status', {
      method: 'PATCH',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify(Object.assign({}, body, { version: t.version }))
    })
      .then(function (response) { return readTicketUpdate(response, 'Unable to update the ticket status.'); })
      .then(function (row) { onDone(normalizeTicket(row)); })
      .catch(function (err) {
        console.error('Status change error:', err);
        if (onError) onError(err);
      });
  }

  // PATCH /api/tickets/:id/csat — same pattern as assignTicket()/
  // changeTicketStatus(): the server is the source of truth, so the caller
  // renders whatever row comes back instead of trusting its own local `t.csat`.
  function submitCsat(ticketId, rating, comment, onDone, onError) {
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(ticketId) + '/csat', {
      method: 'PATCH',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({ csat_rating: rating, csat_comment: comment || null })
    })
      .then(function (response) { return readTicketUpdate(response, 'Unable to submit feedback.'); })
      .then(function (row) { onDone(normalizeTicket(row)); })
      .catch(function (err) {
        console.error('CSAT submit error:', err);
        if (onError) onError(err);
      });
  }

  // ---- Ticket comments (phase 1D-v) ----
  // Public messages, reassignment notes, escalation notes, and resolution
  // notes now live server-side in `ticket_comments` via GET/POST
  // /api/tickets/:id/comments, replacing the old `docketChat:<id>`
  // localStorage thread. That thread never left the browser that wrote it —
  // an agent on a different machine than the one a customer used could never
  // see their messages, and vice versa. Routing everything through the API
  // means every viewer of a ticket (customer, any agent, any admin) now sees
  // the same conversation.

  // The API returns SQLite's `datetime('now')` as "YYYY-MM-DD HH:MM:SS" (UTC,
  // no 'T' separator, no zone) — coerce it into something `Date` parses
  // correctly before formatting, the same h:mm AM/PM format the old chat used.
  function formatCommentTime(raw) {
    // The API now returns real ISO-8601 timestamps (Postgres timestamptz,
    // JSON-serialized) — parses directly, no reformatting needed.
    var d = new Date(String(raw || ''));
    if (isNaN(d.getTime())) return '';
    var h = d.getHours(); var m = d.getMinutes();
    var ampm = h >= 12 ? 'PM' : 'AM';
    h = h % 12; if (h === 0) h = 12;
    return h + ':' + (m < 10 ? '0' : '') + m + ' ' + ampm;
  }

  // Bridges a `ticket_comments` row into the shape the chat thread (and the
  // internal-note callers below) already render: `from`/`name` line up with
  // author_type/author_name, and author_type's values ('customer'/'agent'/
  // 'admin') already match the chat page's own `chatRole` values 1:1.
  function normalizeComment(c) {
    return {
      id: c.id,
      from: c.author_type,
      name: c.author_name,
      text: c.body,
      time: formatCommentTime(c.created_at),
      visibility: c.visibility,
      files: Array.isArray(c.files) ? c.files : []
    };
  }

  // GET /api/tickets/:id/comments — fetched without a `visibility` filter so
  // agent/admin viewers get both public and internal comments in one call;
  // the chat thread itself filters internal notes out for the customer role,
  // same as before.
  function fetchComments(ticketId, onDone, onError) {
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(ticketId) + '/comments', { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) {
          var err = new Error('Unable to load messages.');
          err.status = response.status;
          throw err;
        }
        return response.json();
      })
      .then(function (rows) { onDone(rows.map(normalizeComment)); })
      .catch(function (err) {
        console.error('Comment load error:', err);
        if (onError) onError(err);
      });
  }

  // POST /api/tickets/:id/comments. `visibility` defaults to 'public'
  // server-side; the server also rejects an internal comment authored by a
  // customer, matching the chat composer's own toggle being agent/admin-only.
  function postComment(ticketId, authorType, authorName, text, visibility, files, onDone, onError) {
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(ticketId) + '/comments', {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
      body: JSON.stringify({
        author_type: authorType,
        author_name: authorName,
        visibility: visibility || 'public',
        body: text || '',
        files: files && files.length ? files : undefined
      })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error(data.error || 'Unable to send that message.');
          return data;
        });
      })
      .then(function (row) { onDone(normalizeComment(row)); })
      .catch(function (err) {
        console.error('Comment post error:', err);
        if (onError) onError(err);
      });
  }

  // Shorthand for the system notes the reassign/escalate/resolve/assign
  // flows leave behind — same internal visibility the chat's own toggle
  // uses, just posted directly instead of typed into the composer. Best
  // effort: the underlying assignment/status change has already succeeded
  // by the time this is called, so a note failure is logged, not surfaced,
  // rather than rolling back or blocking on it.
  function postInternalNote(ticketId, authorType, authorName, text) {
    postComment(ticketId, authorType, authorName, text, 'internal', null, function () {}, function (err) {
      console.error('Internal note error:', err);
    });
  }

  // ---- Unread badges (WhatsApp-style) ----
  // The notification poll below gets { total, tickets: { id: n } } back with
  // every response (customers and assigned agents only — see
  // utils/unread.js). applyUnreadBadges() paints it onto whatever is on the
  // page: a count bubble on each ticket row (rows already carry
  // data-ticket-id) and on the "Message support" / "Message customer"
  // button, plus "(3) " in the tab title. The queue renderers call it after
  // each re-render so the badges survive the 4s refresh.
  var unreadState = { total: 0, tickets: {} };
  var unreadOpenChatTicket = window.location.pathname.split('/').pop() === 'ticket-chat.html'
    ? new URLSearchParams(window.location.search).get('ticket')
    : null;
  var baseDocumentTitle = document.title;

  function setUnreadBadge(container, n, prepend) {
    if (!container) return;
    var badge = container.querySelector(':scope > .unread-badge');
    if (!n) { if (badge) badge.remove(); return; }
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'unread-badge';
      if (prepend) container.insertBefore(badge, container.firstChild);
      else container.appendChild(badge);
    }
    badge.textContent = n > 99 ? '99+' : String(n);
    badge.setAttribute('aria-label', n + ' unread message' + (n === 1 ? '' : 's'));
  }

  function applyUnreadBadges() {
    var counts = unreadState.tickets || {};
    document.querySelectorAll('.history-row[data-ticket-id]').forEach(function (row) {
      var n = counts[row.dataset.ticketId] || 0;
      row.classList.toggle('has-unread', n > 0);
      setUnreadBadge(row.querySelector('.history-meta') || row, n, true);
    });
    ['messageAgentBtn', 'messageCustomerBtn'].forEach(function (id) {
      var btn = document.getElementById(id);
      if (!btn) return;
      var href = btn.getAttribute('href') || '';
      var match = href.match(/[?&]ticket=([^&]+)/);
      setUnreadBadge(btn, match ? counts[decodeURIComponent(match[1])] || 0 : 0, false);
    });
    // The conversation open in the chat page is being read right now.
    var total = unreadState.total - (unreadOpenChatTicket ? counts[unreadOpenChatTicket] || 0 : 0);
    document.title = total > 0 ? '(' + (total > 99 ? '99+' : total) + ') ' + baseDocumentTitle : baseDocumentTitle;
  }

  // ---- New-message pop-ups (customer portal, agent/admin consoles, chat) ----
  // Polls GET /api/notifications/messages for messages someone else posted
  // on a ticket this actor can see, and shows each as a toast linking to
  // that ticket's conversation. The cursor (last message id seen) lives in
  // localStorage per actor, so moving between the dashboard and the chat
  // page neither replays old messages nor drops ones that arrived in between.
  (function startMessageNotifier() {
    var page = window.location.pathname.split('/').pop();
    var role = null; // 'customer' | 'agent' | 'admin' — the ticket-chat.html role values
    if (page === 'portal.html' || page === 'ticket.html') role = 'customer';
    else if (page === 'agent-dashboard.html') role = 'agent';
    else if (page === 'admin-dashboard.html') role = 'admin';
    else if (page === 'ticket-chat.html') {
      var r = new URLSearchParams(window.location.search).get('role');
      role = r === 'agent' || r === 'admin' ? r : 'customer';
    }
    if (!role) return;

    // Read this page's own session rather than currentActor(), so testing
    // several roles in one browser doesn't notify the wrong one.
    var actor = null;
    if (role === 'agent') actor = readSession('docketAgent');
    else if (role === 'admin') actor = readSession('docketAdmin');
    else { try { actor = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { actor = null; } }
    if (!actor || !actor.token) return;

    // The chat page already shows new messages for its own ticket live.
    var openChatTicket = page === 'ticket-chat.html' ? new URLSearchParams(window.location.search).get('ticket') : null;
    var cursorKey = 'docketMsgCursor:' + role + ':' + actor.id;
    var cursor = null;
    try { cursor = localStorage.getItem(cursorKey); } catch (e) { cursor = null; }

    var stack = document.createElement('div');
    stack.className = 'toast-stack';
    stack.setAttribute('aria-live', 'polite');
    document.body.appendChild(stack);

    function escapeText(str) {
      var div = document.createElement('div');
      div.textContent = str == null ? '' : String(str);
      return div.innerHTML;
    }

    // ---- Browser (system) notifications ----
    // Shown in addition to the toast whenever this tab isn't visible, so a
    // message still gets noticed with the console in a background tab or
    // behind another window. Browsers only allow asking for permission from
    // a click, so an "Enable" card is offered once until it's answered or
    // dismissed. Needs a secure context (https or localhost).
    var canNotify = 'Notification' in window && window.isSecureContext;
    var promptDismissedKey = 'docketNotifyPromptDismissed';

    function offerBrowserNotifications() {
      if (!canNotify || Notification.permission !== 'default') return;
      try { if (localStorage.getItem(promptDismissedKey)) return; } catch (e) { /* show it anyway */ }

      var card = document.createElement('div');
      card.className = 'toast toast-prompt';
      card.innerHTML =
        '<button class="toast-close" type="button" aria-label="Dismiss">×</button>' +
        '<p class="toast-from">Get notified about new messages?</p>' +
        '<p class="toast-body">Turn on browser notifications to hear about new ticket messages even when this tab is in the background.</p>' +
        '<button class="btn-amber btn-inline toast-enable" type="button">Enable notifications</button>';

      function close(remember) {
        if (remember) { try { localStorage.setItem(promptDismissedKey, '1'); } catch (e) { /* ignore */ } }
        if (card.parentNode) card.parentNode.removeChild(card);
      }
      card.querySelector('.toast-close').addEventListener('click', function () { close(true); });
      card.querySelector('.toast-enable').addEventListener('click', function () {
        // Older Safari only supports the callback form, not the Promise.
        var result = Notification.requestPermission(function () { close(false); });
        if (result && result.then) result.then(function () { close(false); });
      });
      stack.appendChild(card);
    }

    function showBrowserNotification(m, preview, link) {
      if (!canNotify || Notification.permission !== 'granted' || !document.hidden) return;
      try {
        var n = new Notification(
          (m.visibility === 'internal' ? 'Internal note' : 'New message') + ' · ' + m.ticket_id,
          {
            body: m.author_name + ': ' + (preview || m.subject),
            // Same tag in every open tab, so one message = one notification.
            tag: 'docket-msg-' + m.id
          }
        );
        n.onclick = function () { window.focus(); window.location.href = link; n.close(); };
      } catch (e) {
        // Some mobile browsers only allow notifications via a service worker.
        console.error('Browser notification failed:', e);
      }
    }

    function showToast(m) {
      var preview = m.body ? m.body : (m.file_count ? '📎 ' + m.file_count + ' attachment' + (m.file_count === 1 ? '' : 's') : '');
      if (preview.length > 140) preview = preview.slice(0, 140) + '…';
      var internal = m.visibility === 'internal';
      var link = 'ticket-chat.html?ticket=' + encodeURIComponent(m.ticket_id) + '&role=' + role;
      showBrowserNotification(m, preview, link);

      var toast = document.createElement('a');
      toast.className = 'toast' + (internal ? ' toast-internal' : '');
      toast.href = link;
      toast.innerHTML =
        '<button class="toast-close" type="button" aria-label="Dismiss">×</button>' +
        '<p class="toast-title">' + (internal ? 'New internal note' : 'New message') + ' · ' + escapeText(m.ticket_id) + '</p>' +
        '<p class="toast-from">' + escapeText(m.author_name) + ' <span>on "' + escapeText(m.subject) + '"</span></p>' +
        (preview ? '<p class="toast-body">' + escapeText(preview) + '</p>' : '') +
        '<p class="toast-cta">Open conversation →</p>';

      function dismiss() {
        toast.classList.add('toast-out');
        setTimeout(function () { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 250);
      }
      toast.querySelector('.toast-close').addEventListener('click', function (e) {
        e.preventDefault(); e.stopPropagation(); dismiss();
      });
      stack.appendChild(toast);
      // Keep at most 4 message toasts on screen; the oldest goes first.
      var toasts = stack.querySelectorAll('.toast:not(.toast-prompt)');
      for (var i = 0; i < toasts.length - 4; i++) stack.removeChild(toasts[i]);
      setTimeout(dismiss, 10000);
    }

    function poll() {
      var url = API_BASE + '/api/notifications/messages' + (cursor != null ? '?after_id=' + encodeURIComponent(cursor) : '');
      fetch(url, { headers: { 'Authorization': 'Bearer ' + actor.token } })
        .then(function (response) {
          if (!response.ok) throw new Error('notification poll failed (' + response.status + ')');
          return response.json();
        })
        .then(function (data) {
          (data.messages || []).forEach(function (m) {
            if (m.ticket_id !== openChatTicket) showToast(m);
          });
          if (data.unread) {
            unreadState = data.unread;
            applyUnreadBadges();
          }
          cursor = String(data.latest_id);
          try { localStorage.setItem(cursorKey, cursor); } catch (e) { /* cursor just won't persist */ }
        })
        .catch(function (err) { console.error('Message notifications:', err); });
    }

    offerBrowserNotifications();
    poll();
    setInterval(poll, 5000);
  })();

  // Swap a server-updated ticket into an in-memory list, in place.
  function replaceTicketIn(list, updated) {
    var idx = list.findIndex(function (x) { return x.id === updated.id; });
    if (idx !== -1) list[idx] = updated;
    return list;
  }

  // The inline assign/reassign panels only had field-level `.err` slots, with
  // nothing for a failed request, so the error element is created on first use.
  function showPanelError(panel, message) {
    if (!panel) return;
    var box = panel.querySelector('.panel-error');
    if (!box) {
      box = document.createElement('p');
      box.className = 'err panel-error';
      box.style.display = 'block';
      box.style.marginBottom = '12px';
      panel.insertBefore(box, panel.firstChild);
    }
    box.textContent = message;
  }

  function clearPanelError(panel) {
    if (!panel) return;
    var box = panel.querySelector('.panel-error');
    if (box) box.remove();
  }

  // GET /api/tickets, optionally filtered — e.g. { user_id: 'USR-000001' } for
  // the customer portal, or no filter at all for the agent/admin queues.
  function fetchTickets(query, onDone, onError) {
    var qs = '';
    if (query) {
      var parts = [];
      Object.keys(query).forEach(function (k) {
        if (query[k]) parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(query[k]));
      });
      if (parts.length) qs = '?' + parts.join('&');
    }
    fetch(API_BASE + '/api/tickets' + qs, { headers: authHeaders() })
      .then(function (response) {
        if (!response.ok) {
          var err = new Error('Unable to load tickets.');
          err.status = response.status;
          throw err;
        }
        return response.json();
      })
      .then(function (rows) { onDone(rows.map(normalizeTicket)); })
      .catch(function (err) {
        console.error('Ticket load error:', err);
        if (onError) onError(err);
      });
  }

  // Retries a failed fetchTickets() with backoff before finally calling
  // onError — used for the agent/admin queues' initial load, where a Render
  // free-tier cold start can make the very first request time out even
  // though the API is otherwise fine. Without this, that timeout renders
  // exactly like a genuinely empty queue (see bootstrapAgentQueue/
  // bootstrapAdminConsole's separate `failed` state, which this feeds).
  function fetchTicketsWithRetry(query, onDone, onError, attempt) {
    attempt = attempt || 0;
    var delays = [2000, 5000]; // wait 2s, then 5s, before giving up
    fetchTickets(query, onDone, function (err) {
      // A 401 (expired/missing token) will never succeed on retry — only
      // retry for a transient failure (e.g. a Render cold start).
      if (err.status !== 401 && attempt < delays.length) {
        setTimeout(function () {
          fetchTicketsWithRetry(query, onDone, onError, attempt + 1);
        }, delays[attempt]);
      } else if (onError) {
        onError(err);
      }
    });
  }

  // Agent sign-in (agent-login.html): POST /api/agents looks the agent up by
  // email (agents are invite-only — an unknown email gets an error, not a new
  // account), and there's no agent password on the backend — the emailed MFA
  // code is what actually proves the agent owns the address. The client-side
  // password check stays as-is (just requires something typed).
  function loginOrCreateAgentByEmail(email, fallbackName, onDone, onError) {
    fetch(API_BASE + '/api/agents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ full_name: fallbackName, email: email, created_by: 'self-signup' })
    })
      .then(function (response) {
        return response.json().then(function (data) {
          if (!response.ok) throw new Error(data.error || 'Unable to sign in.');
          return data;
        });
      })
      .then(function (challenge) {
        return promptForMfaCode(challenge, email);
      })
      .then(function (verified) {
        var agent = normalizeAgent(verified.record);
        agent.token = verified.token;
        onDone(agent);
      })
      .catch(onError);
  }

  // ---- Agent sign-in (agent-login.html): validation + confirmation stub ----
  var agentLoginForm = document.getElementById('agentLoginForm');
  if (agentLoginForm) {
    var submitAgentLoginBtn = document.getElementById('submitAgentLogin');
    var submitAgentLoginDefaultLabel = submitAgentLoginBtn.textContent;

    submitAgentLoginBtn.addEventListener('click', function () {
      var email = document.getElementById('agentEmail');
      var password = document.getElementById('agentPassword');
      var valid = true;

      var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value.trim());
      if (!emailOk) {
        document.getElementById('f-agentEmail').classList.add('invalid');
        valid = false;
      } else {
        document.getElementById('f-agentEmail').classList.remove('invalid');
      }

      if (!password.value.trim()) {
        document.getElementById('f-agentPassword').classList.add('invalid');
        valid = false;
      } else {
        document.getElementById('f-agentPassword').classList.remove('invalid');
      }

      if (!valid) return;

      var namePart = email.value.trim().split('@')[0].replace(/[._]/g, ' ');
      var displayName = namePart.replace(/\b\w/g, function (c) { return c.toUpperCase(); });

      submitAgentLoginBtn.disabled = true;
      submitAgentLoginBtn.textContent = 'Signing in…';

      // Only works for an email an admin has already added from the admin console.
      loginOrCreateAgentByEmail(email.value.trim(), displayName, function (record) {
        submitAgentLoginBtn.disabled = false;
        submitAgentLoginBtn.textContent = submitAgentLoginDefaultLabel;

        document.getElementById('agentStubId').textContent = record.id;
        document.getElementById('agentStubName').textContent = ', ' + record.name.split(' ')[0];
        agentLoginForm.style.display = 'none';
        document.getElementById('agentStub').classList.add('show');

        saveSession('docketAgent', {
          id: record.id,
          name: record.name,
          email: record.email,
          token: record.token
        }, document.getElementById('keepSignedIn').checked);
      }, function (err) {
        submitAgentLoginBtn.disabled = false;
        submitAgentLoginBtn.textContent = submitAgentLoginDefaultLabel;
        if (err.cancelled) return;
        console.error('Agent sign-in error:', err);
        document.getElementById('f-agentEmail').classList.add('invalid');
        alert(err.message || 'Unable to sign in. Please try again.');
      });
    });
  }
// ---- Admin sign-in (admin-login.html): single seeded super account, validation + confirmation stub ----
  var adminLoginForm = document.getElementById('adminLoginForm');
  if (adminLoginForm) {
    var submitAdminLoginBtn = document.getElementById('submitAdminLogin');
    var submitAdminLoginDefaultLabel = submitAdminLoginBtn.textContent;

    submitAdminLoginBtn.addEventListener('click', function () {
      var email = document.getElementById('adminEmail');
      var password = document.getElementById('adminPassword');
      var emailField = document.getElementById('f-adminEmail');
      var passwordField = document.getElementById('f-adminPassword');
      var emailErr = document.getElementById('err-adminEmail');
      var passwordErr = document.getElementById('err-adminPassword');

      // Reset to the default "required" messaging before re-checking
      emailErr.textContent = 'Enter your admin email address.';
      passwordErr.textContent = 'Enter your password.';

      var valid = true;
      if (!email.value.trim()) { emailField.classList.add('invalid'); valid = false; }
      else { emailField.classList.remove('invalid'); }

      if (!password.value.trim()) { passwordField.classList.add('invalid'); valid = false; }
      else { passwordField.classList.remove('invalid'); }

      if (!valid) return;

      submitAdminLoginBtn.disabled = true;
      submitAdminLoginBtn.textContent = 'Signing in…';

      // Real bcrypt check on Render now — this is the one login the backend
      // actually verifies (agents.js has no password at all; see Phase 1B).
      // Same generic "incorrect email or password" message either way, since
      // the server itself doesn't say which one was wrong.
      fetch(API_BASE + '/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.value.trim(), password: password.value, role: 'admin' })
      })
        .then(function (response) {
          return response.json().then(function (data) {
            // 401 stays generic (don't say which half was wrong); anything
            // else — rate limit, email send failure — shows the real reason.
            if (response.status === 401) throw new Error('Incorrect email or password.');
            if (!response.ok) throw new Error(data.error || 'Unable to sign in.');
            return data;
          });
        })
        .then(function (challenge) {
          return promptForMfaCode(challenge, email.value.trim());
        })
        .then(function (data) {
          var admin = { id: data.actor.id, name: data.actor.full_name, email: data.actor.email, token: data.token };

          document.getElementById('adminStubId').textContent = admin.id;
          document.getElementById('adminStubName').textContent = ', ' + admin.name.split(' ')[0];
          adminLoginForm.style.display = 'none';
          document.getElementById('adminStub').classList.add('show');

          saveSession('docketAdmin', {
            id: admin.id,
            name: admin.name,
            email: admin.email,
            token: admin.token
          }, document.getElementById('adminKeepSignedIn').checked);
        })
        .catch(function (err) {
          if (err.cancelled) return;
          emailField.classList.add('invalid');
          passwordField.classList.add('invalid');
          emailErr.textContent = err.message || 'Incorrect email or password.';
          passwordErr.textContent = err.message || 'Incorrect email or password.';
        })
        .finally(function () {
          submitAdminLoginBtn.disabled = false;
          submitAdminLoginBtn.textContent = submitAdminLoginDefaultLabel;
        });
    });

    var adminForgotLink = document.getElementById('adminForgotPassword');
    if (adminForgotLink) {
      adminForgotLink.addEventListener('click', function (e) {
        e.preventDefault();
        promptForPasswordReset('admin', document.getElementById('adminEmail').value.trim());
      });
    }
  }

  // ---- Forgot password: emails a reset link (POST /api/auth/password-reset/request) ----
  // Reuses the MFA dialog's overlay styling. The server answers the same way
  // whether or not the email has an account, so the dialog does too.
  function promptForPasswordReset(role, prefillEmail) {
    var overlay = document.createElement('div');
    overlay.className = 'mfa-overlay';
    overlay.innerHTML =
      '<div class="mfa-dialog" role="dialog" aria-modal="true" aria-labelledby="resetTitle">' +
        '<h2 id="resetTitle">Reset your password</h2>' +
        '<p class="lead">Enter your account email and we\'ll send you a link to choose a new password.</p>' +
        '<div class="field" id="f-resetEmail">' +
          '<label for="resetEmail">Email</label>' +
          '<input type="email" id="resetEmail" autocomplete="email">' +
          '<div class="err" id="err-resetEmail">Enter a valid email address.</div>' +
        '</div>' +
        '<button class="btn-amber" type="button" id="resetSend">Send reset link</button>' +
        '<div class="mfa-status" id="resetStatus" aria-live="polite"></div>' +
        '<div class="mfa-actions"><span></span><a href="#" id="resetClose">Close</a></div>' +
      '</div>';
    document.body.appendChild(overlay);

    var input = overlay.querySelector('#resetEmail');
    var field = overlay.querySelector('#f-resetEmail');
    var errEl = overlay.querySelector('#err-resetEmail');
    var sendBtn = overlay.querySelector('#resetSend');
    var statusEl = overlay.querySelector('#resetStatus');
    input.value = prefillEmail || '';
    input.focus();

    function close() {
      document.removeEventListener('keydown', onKeydown);
      overlay.remove();
    }
    function onKeydown(e) {
      if (e.key === 'Escape') { e.preventDefault(); close(); }
    }

    function send() {
      if (sendBtn.disabled) return;
      var email = input.value.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errEl.textContent = 'Enter a valid email address.';
        field.classList.add('invalid');
        return;
      }
      field.classList.remove('invalid');
      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending…';
      statusEl.textContent = '';

      postJson('/api/auth/password-reset/request', { email: email, role: role })
        .then(function (res) {
          if (!res.ok) throw new Error(res.data.error || 'Unable to send a reset link.');
          statusEl.textContent = res.data.message || 'Check your inbox for a reset link.';
          sendBtn.textContent = 'Link sent';
        })
        .catch(function (err) {
          errEl.textContent = err.message && err.message !== 'Failed to fetch' ? err.message : 'Network error. Please try again.';
          field.classList.add('invalid');
          sendBtn.disabled = false;
          sendBtn.textContent = 'Send reset link';
        });
    }

    sendBtn.addEventListener('click', send);
    input.addEventListener('keydown', function (e) { if (e.key === 'Enter') send(); });
    overlay.querySelector('#resetClose').addEventListener('click', function (e) { e.preventDefault(); close(); });
    document.addEventListener('keydown', onKeydown);
  }

  // ---- Reset password (reset-password.html): token from the emailed link's #fragment ----
  var resetPasswordForm = document.getElementById('resetPasswordForm');
  if (resetPasswordForm) {
    var resetToken = new URLSearchParams(window.location.hash.slice(1)).get('token');
    // Drop the token from the address bar/history now that it's been read.
    if (window.history.replaceState) window.history.replaceState(null, '', window.location.pathname);

    var newPassword = document.getElementById('newPassword');
    var confirmPassword = document.getElementById('confirmPassword');
    var newPasswordField = document.getElementById('f-newPassword');
    var confirmPasswordField = document.getElementById('f-confirmPassword');
    var newPasswordErr = document.getElementById('err-newPassword');
    var submitResetBtn = document.getElementById('submitResetPassword');
    var submitResetDefaultLabel = submitResetBtn.textContent;
    var loginPageByRole = { admin: 'admin-login.html', agent: 'agent-login.html', user: 'login.html' };

    if (!resetToken) {
      newPasswordErr.textContent = 'This reset link is incomplete. Open the link from your email again, or request a new one.';
      newPasswordField.classList.add('invalid');
      submitResetBtn.disabled = true;
    }

    function submitReset() {
      if (submitResetBtn.disabled) return;
      newPasswordErr.textContent = 'Use at least 8 characters.';
      var valid = true;
      if (newPassword.value.length < 8) { newPasswordField.classList.add('invalid'); valid = false; }
      else { newPasswordField.classList.remove('invalid'); }
      if (confirmPassword.value !== newPassword.value) { confirmPasswordField.classList.add('invalid'); valid = false; }
      else { confirmPasswordField.classList.remove('invalid'); }
      if (!valid) return;

      submitResetBtn.disabled = true;
      submitResetBtn.textContent = 'Saving…';

      postJson('/api/auth/password-reset/confirm', { token: resetToken, password: newPassword.value })
        .then(function (res) {
          if (!res.ok) throw new Error(res.data.error || 'Unable to reset your password.');
          document.getElementById('resetPasswordSignIn').href = loginPageByRole[res.data.role] || 'login.html';
          resetPasswordForm.style.display = 'none';
          document.getElementById('resetPasswordStub').classList.add('show');
        })
        .catch(function (err) {
          newPasswordErr.textContent = err.message && err.message !== 'Failed to fetch' ? err.message : 'Network error. Please try again.';
          newPasswordField.classList.add('invalid');
          submitResetBtn.disabled = false;
          submitResetBtn.textContent = submitResetDefaultLabel;
        });
    }

    submitResetBtn.addEventListener('click', submitReset);
    confirmPassword.addEventListener('keydown', function (e) { if (e.key === 'Enter') submitReset(); });
  }

  // ---- Ticket creation (ticket.html): form + submitting animation, then hands off to portal.html ----
  var ticketForm = document.getElementById('ticketForm');
  if (ticketForm) {
    var user = null;
    try { user = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { user = null; }
    if (user && document.getElementById('requesterLine')) {
      document.getElementById('requesterLine').textContent = 'Filing as ' + user.name + ' (' + user.id + ')';
    }

    // The portal's help bot links here with ?priority=, ?category= and
    // ?service= to pre-fill the form. A select only takes a value that's one
    // of its own options; the customer can still change anything.
    var prefill = new URLSearchParams(window.location.search);
    ['priority', 'category'].forEach(function (key) {
      var select = document.getElementById(key);
      var value = prefill.get(key);
      if (select && value && Array.prototype.some.call(select.options, function (o) { return o.value === value; })) {
        select.value = value;
      }
    });
    var serviceInput = document.getElementById('service');
    if (serviceInput && prefill.get('service')) serviceInput.value = prefill.get('service').slice(0, 120);

    var files = [];
    var fileInput = document.getElementById('attachments');
    var fileList = document.getElementById('fileList');
    if (fileInput) {
      fileInput.addEventListener('change', function () {
        Array.prototype.forEach.call(fileInput.files, function (f) { files.push(f); });
        fileInput.value = '';
        renderFiles();
      });
    }
    function renderFiles() {
      fileList.innerHTML = '';
      files.forEach(function (file, i) {
        var chip = document.createElement('span');
        chip.className = 'file-chip';
        chip.innerHTML = '<span>' + escapeHtml(file.name) + '</span>';
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Remove ' + file.name);
        btn.textContent = '✕';
        btn.addEventListener('click', function () { files.splice(i, 1); renderFiles(); });
        chip.appendChild(btn);
        fileList.appendChild(chip);
      });
    }

    // The category -> team and priority -> SLA tables used to live here and
    // are now owned by the server (see TEAM_BY_CATEGORY / SLA_BY_PRIORITY in
    // routes/tickets.js), so the client no longer keeps its own copies.

    document.getElementById('submitTicket').addEventListener('click', function () {
      var subject = document.getElementById('subject');
      var description = document.getElementById('description');
      var category = document.getElementById('category');
      var priority = document.getElementById('priority');
      var service = document.getElementById('service');
      var valid = true;

      [[subject, 'f-subject'], [description, 'f-description'], [category, 'f-category'], [priority, 'f-priority']]
        .forEach(function (pair) {
          var field = document.getElementById(pair[1]);
          if (!pair[0].value.trim()) { field.classList.add('invalid'); valid = false; }
          else { field.classList.remove('invalid'); }
        });

      if (!valid) return;

      ticketForm.style.display = 'none';
      var pipeline = document.getElementById('pipeline');
      pipeline.classList.add('show');

      var steps = document.querySelectorAll('.pipe-step');
      var delays = [0, 500, 1000, 1500, 2000];
      steps.forEach(function (s, i) {
        setTimeout(function () { s.classList.add('active'); }, delays[i] || i * 500);
      });

      // The POST fires immediately and the pipeline animation runs alongside
      // it; the redirect waits for whichever finishes last, so the row really
      // exists in the database before portal.html tries to read it back.
      var animationDone = false;
      var createdTicket = null;

      function maybeGoToPortal() {
        if (!animationDone || !createdTicket) return;
        // The portal used to be handed a whole ticket object through
        // `docketLatestTicket`; now it only needs to know which of the
        // tickets it fetches should open as the headline card.
        localStorage.setItem('docketLatestTicketId', createdTicket.id);
        window.location.href = 'portal.html';
      }

      // ticket.html has no error slot of its own — the form only had per-field
      // `.err` messages — so on failure we drop back to the form and put a
      // message above it rather than leaving the user on a stalled pipeline.
      function showSubmitError(message) {
        pipeline.classList.remove('show');
        ticketForm.style.display = '';
        var box = document.getElementById('ticketSubmitError');
        if (!box) {
          box = document.createElement('p');
          box.id = 'ticketSubmitError';
          box.className = 'err';
          box.style.display = 'block';
          box.style.marginBottom = '16px';
          ticketForm.insertBefore(box, document.getElementById('f-subject'));
        }
        box.textContent = message;
      }

      setTimeout(function () { animationDone = true; maybeGoToPortal(); }, 2600);

      // Read every selected file into base64 before the POST — a read
      // failure (e.g. over the 5MB cap) aborts the submission the same way
      // a validation error does, rather than sending a partial attachment
      // list.
      Promise.all(files.map(readFileAsAttachment))
        .then(function (attachments) {
          return fetch(API_BASE + '/api/tickets', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
            body: JSON.stringify({
              user_id: user ? user.id : null,
              subject: subject.value.trim(),
              description: description.value.trim(),
              category: category.value,
              priority: priority.value,
              affected_service: service && service.value.trim() ? service.value.trim() : null,
              attachments: attachments
            })
          });
        })
        .then(function (response) {
          return response.json().then(function (data) {
            if (!response.ok) throw new Error(data.error || 'Unable to create the ticket.');
            return data;
          });
        })
        .then(function (data) {
          createdTicket = data;
          maybeGoToPortal();
        })
        .catch(function (err) {
          console.error('Ticket create error:', err);
          showSubmitError(err.message || 'Unable to create the ticket. Please try again.');
        });
    });
  }

  // ---- Ticket portal (portal.html): profile sidebar + latest ticket + full, clickable history ----
  var dash = document.getElementById('dash');
  if (dash) {
    var portalUser = null;
    try { portalUser = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { portalUser = null; }

    // Both of these start empty and are filled by the fetch at the bottom of
    // this block. `latestTicketId` is all ticket.html hands over now — the
    // ticket itself is read back from the API rather than passed through
    // localStorage.
    var latestTicketId = localStorage.getItem('docketLatestTicketId');
    var latest = null;
    var all = [];

    // Snapshot of each ticket's status as this tab currently knows it, so a
    // change made elsewhere (an agent updating status on their dashboard, or
    // this same customer with the portal open in a second tab) can be told
    // apart from a status this tab already displayed.
    var knownStatuses = {};

    function portalStatusClass(status) {
      if (status === 'Resolved') return 'status-resolved';
      if (status === 'Closed') return 'status-closed';
      if (status === 'Reopened') return 'status-reopened';
      if (status === 'In Progress') return 'status-progress';
      if (status === 'Waiting') return 'status-waiting';
      if (status === 'Escalated') return 'status-escalated';
      return '';
    }

    // Keeps the page's in-memory copies (`all` / `latest`) in sync with a
    // ticket the server just confirmed, so the rest of the page's rendering
    // (history list, filters, active-row highlight) reflects it without a
    // refetch. Confirm-fix and reopen call this with the server's response,
    // not a locally-guessed status. (CSAT's own persistence is still open —
    // see routes/tickets.js's /csat endpoint, not yet called from here.)
    function persistPortalTicket(t) {
      var idx = all.findIndex(function (x) { return x.id === t.id; });
      if (idx !== -1) all[idx] = t;
      if (latest && latest.id === t.id) latest = t;
    }

    // A refused update (409) carries the ticket as it is now: show that and
    // say why nothing happened. False for any other error.
    function showLatestPortalTicket(err) {
      if (!err || !err.latest) return false;
      persistPortalTicket(err.latest);
      showTicketDetails(err.latest);
      alert(err.message);
      return true;
    }

    // Profile sidebar
    var profileSidebar = document.getElementById('profileSidebar');
    if (profileSidebar) {
      if (portalUser && portalUser.name) {
        var initials = portalUser.name.trim().split(/\s+/).map(function (p) { return p[0]; }).slice(0, 2).join('').toUpperCase();
        document.getElementById('profileInitials').textContent = initials || '?';
        document.getElementById('profileName').textContent = portalUser.name;
        document.getElementById('profileId').textContent = portalUser.id;
        document.getElementById('profileEmail').textContent = portalUser.email;
        // Filled in once the fetch below resolves.
        document.getElementById('profileTicketCount').textContent = '—';
      } else {
        profileSidebar.style.display = 'none';
      }
    }

    // Loads a ticket's full details into the dashboard card and highlights its row
    var currentTicketId = null;
    function showTicketDetails(t) {
      currentTicketId = t.id;
      document.getElementById('dashId').textContent = t.id;
      document.getElementById('dashSubject').textContent = t.subject;
      document.getElementById('dashDescription').textContent = t.description ? t.description : 'No description provided.';
      document.getElementById('dashCategory').textContent = t.category;
      document.getElementById('dashPriority').textContent = t.priority;
      document.getElementById('dashTeam').textContent = t.team;
      document.getElementById('dashSla').textContent = t.sla;
      document.getElementById('dashFiles').textContent = t.files ? t.files + ' attached' : 'None';
      document.getElementById('dashEmail').textContent = t.email;
      document.getElementById('dashAgent').textContent = t.assignedAgent || 'Unassigned';

      var dashAttBlock = document.getElementById('dashAttachmentsBlock');
      if (dashAttBlock) {
        if (t.attachments && t.attachments.length) {
          renderAttachmentChips(document.getElementById('dashAttachmentsList'), t.attachments);
          dashAttBlock.style.display = '';
        } else {
          dashAttBlock.style.display = 'none';
        }
      }

      var serviceBox = document.getElementById('dashServiceBox');
      if (serviceBox) {
        if (t.service) {
          document.getElementById('dashService').textContent = t.service;
          serviceBox.style.display = '';
        } else {
          serviceBox.style.display = 'none';
        }
      }

      var statusBadge = document.getElementById('dashStatusBadge');
      statusBadge.textContent = t.status || 'Assigned';
      statusBadge.className = 'status-badge ' + portalStatusClass(t.status);

      var messageAgentBtn = document.getElementById('messageAgentBtn');
      if (messageAgentBtn) messageAgentBtn.setAttribute('href', 'ticket-chat.html?ticket=' + encodeURIComponent(t.id) + '&role=customer');
      applyUnreadBadges();

      // Confirm fix / reopen only apply while a ticket is sitting in "Resolved",
      // waiting on the customer to say whether the fix actually worked.
      var resolutionRow = document.getElementById('resolutionRow');
      var notifyBanner = document.getElementById('dashNotifyBanner');
      if (resolutionRow) {
        resolutionRow.style.display = t.status === 'Resolved' ? 'flex' : 'none';
      }
      if (notifyBanner) {
        var bannerText = notifyBanner.querySelector('p');
        if (t.status === 'Closed') {
          bannerText.innerHTML = 'You confirmed the fix for <strong id="dashEmail">' + escapeHtml(t.email) + '</strong> — this ticket is closed.';
        } else if (t.status === 'Reopened') {
          bannerText.innerHTML = 'You reopened this ticket — <strong id="dashEmail">' + escapeHtml(t.email) + '</strong> has been notified.';
        } else {
          bannerText.innerHTML = 'Confirmation sent to <strong id="dashEmail">' + escapeHtml(t.email) + '</strong> via the notification service.';
        }
      }

      // Show what the agent said fixed the issue, once they've resolved it —
      // this stays visible even if the ticket later gets reopened.
      var resSummaryBlock = document.getElementById('dashResolutionSummaryBlock');
      var resSummaryText = document.getElementById('dashResolutionSummaryText');
      if (resSummaryBlock && resSummaryText) {
        if (t.resolutionSummary) {
          resSummaryText.textContent = t.resolutionSummary.text;
          resSummaryBlock.style.display = 'block';
        } else {
          resSummaryBlock.style.display = 'none';
        }
      }

      // CSAT: prompt for a rating once a ticket is Closed and unrated; show the
      // submitted rating (read-only) once one exists.
      var csatPanel = document.getElementById('csatPanel');
      var csatDone = document.getElementById('csatDone');
      if (csatPanel && csatDone) {
        if (t.status === 'Closed' && !t.csat) {
          csatPanel.style.display = 'block';
          csatDone.style.display = 'none';
          resetCsatForm();
        } else if (t.status === 'Closed' && t.csat) {
          csatPanel.style.display = 'none';
          csatDone.style.display = 'flex';
          renderCsatDone(t.csat);
        } else {
          csatPanel.style.display = 'none';
          csatDone.style.display = 'none';
        }
      }

      // Re-render the (filtered) history list so status changes and the
      // active-row highlight both stay in sync with what's currently shown.
      renderHistoryList();
    }

    var confirmFixBtn = document.getElementById('confirmFixBtn');
    if (confirmFixBtn) {
      confirmFixBtn.addEventListener('click', function () {
        var t = all.filter(function (x) { return x.id === currentTicketId; })[0];
        if (!t) return;
        confirmFixBtn.disabled = true;
        changeTicketStatus(t, { status: 'Closed' }, function (updated) {
          confirmFixBtn.disabled = false;
          persistPortalTicket(updated);
          showTicketDetails(updated);
        }, function (err) {
          confirmFixBtn.disabled = false;
          if (showLatestPortalTicket(err)) return;
          alert(err.message || 'Unable to confirm the fix. Please try again.');
        });
      });
    }

    var reopenBtn = document.getElementById('reopenBtn');
    if (reopenBtn) {
      reopenBtn.addEventListener('click', function () {
        var t = all.filter(function (x) { return x.id === currentTicketId; })[0];
        if (!t) return;
        reopenBtn.disabled = true;
        changeTicketStatus(t, { status: 'Reopened' }, function (updated) {
          reopenBtn.disabled = false;
          persistPortalTicket(updated);
          showTicketDetails(updated);
        }, function (err) {
          reopenBtn.disabled = false;
          if (showLatestPortalTicket(err)) return;
          alert(err.message || 'Unable to reopen the ticket. Please try again.');
        });
      });
    }

    // ---- CSAT rating (shown on a Closed ticket until the customer rates it) ----
    var csatSelected = 0;
    var csatStarEls = document.querySelectorAll('#csatStars .csat-star');
    var csatSubmitBtn = document.getElementById('csatSubmitBtn');
    var csatCommentEl = document.getElementById('csatComment');

    function paintCsatStars(upTo) {
      csatStarEls.forEach(function (star) {
        star.classList.toggle('active', Number(star.dataset.value) <= upTo);
      });
    }

    function resetCsatForm() {
      csatSelected = 0;
      paintCsatStars(0);
      if (csatSubmitBtn) csatSubmitBtn.disabled = true;
      if (csatCommentEl) csatCommentEl.value = '';
    }

    function renderCsatDone(csat) {
      var doneStars = document.getElementById('csatDoneStars');
      var doneText = document.getElementById('csatDoneText');
      if (doneStars) {
        doneStars.innerHTML = '';
        for (var i = 1; i <= 5; i++) {
          var s = document.createElement('span');
          s.className = 'csat-star' + (i <= csat.score ? ' active' : '');
          s.textContent = '★';
          doneStars.appendChild(s);
        }
      }
      if (doneText) {
        doneText.innerHTML = 'You rated this ticket <strong>' + escapeHtml(csat.score) + '/5</strong>' +
          (csat.comment ? ' — thanks for the note!' : ' — thanks for the feedback!');
      }
    }

    csatStarEls.forEach(function (star) {
      star.addEventListener('click', function () {
        csatSelected = Number(star.dataset.value);
        paintCsatStars(csatSelected);
        if (csatSubmitBtn) csatSubmitBtn.disabled = false;
      });
      star.addEventListener('mouseenter', function () { paintCsatStars(Number(star.dataset.value)); });
      star.addEventListener('mouseleave', function () { paintCsatStars(csatSelected); });
    });

    if (csatSubmitBtn) {
      csatSubmitBtn.addEventListener('click', function () {
        if (!csatSelected) return;
        var t = all.filter(function (x) { return x.id === currentTicketId; })[0];
        if (!t) return;
        var comment = csatCommentEl ? csatCommentEl.value.trim() : '';
        csatSubmitBtn.disabled = true;
        submitCsat(t.id, csatSelected, comment, function (updated) {
          replaceTicketIn(all, updated);
          showTicketDetails(updated);
        }, function (err) {
          csatSubmitBtn.disabled = false;
          if (showLatestPortalTicket(err)) return;
          alert('Could not submit your feedback — please try again.');
        });
      });
    }

    // FR-15: search + status/category filters over "Your tickets" — previously
    // a flat, unfiltered dump of every ticket, unlike the agent/admin queues
    // which both already had search + filters over the same kind of list.
    var historySection = document.getElementById('ticketHistory');
    var historyListEl = document.getElementById('historyList');
    var portalQueueSearchInput = document.getElementById('portalQueueSearchInput');
    var portalQueueStatusFilter = document.getElementById('portalQueueStatusFilter');
    var portalQueueCategoryFilter = document.getElementById('portalQueueCategoryFilter');
    var portalQueueClearFilters = document.getElementById('portalQueueClearFilters');
    var portalSearchQuery = '', portalStatusFilter = '', portalCategoryFilter = '';

    function renderHistoryList() {
      if (!historySection || !historyListEl) return;
      if (!all.length) { historySection.style.display = 'none'; return; }
      historySection.style.display = 'block';

      var q = portalSearchQuery.trim().toLowerCase();
      var filtered = all.filter(function (t) {
        if (portalStatusFilter && t.status !== portalStatusFilter) return false;
        if (portalCategoryFilter && t.category !== portalCategoryFilter) return false;
        if (q) {
          var haystack = (t.id + ' ' + t.subject + ' ' + (t.category || '')).toLowerCase();
          if (haystack.indexOf(q) === -1) return false;
        }
        return true;
      });

      historyListEl.innerHTML = '';
      if (!filtered.length) {
        historyListEl.innerHTML = '<p class="queue-no-results">No tickets match your search or filters.</p>';
        return;
      }

      filtered.forEach(function (t) {
        var row = document.createElement('div');
        row.className = 'history-row ' + portalStatusClass(t.status) + (t.id === currentTicketId ? ' active' : '');
        row.dataset.ticketId = t.id;
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        row.setAttribute('aria-label', 'View details for ' + t.subject);
        row.innerHTML =
          '<div class="history-main">' +
            '<p class="history-id">' + escapeHtml(t.id) + '</p>' +
            '<p class="history-subject">' + escapeHtml(t.subject) + '</p>' +
          '</div>' +
          '<div class="history-meta">' +
            '<span class="history-chip">' + escapeHtml(t.category) + '</span>' +
            '<span class="history-chip">' + escapeHtml(t.priority) + '</span>' +
            '<span class="history-chip">' + escapeHtml(t.team) + '</span>' +
            '<span class="history-status">' + escapeHtml(t.status) + '</span>' +
          '</div>';
        row.addEventListener('click', function () { showTicketDetails(t); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showTicketDetails(t); }
        });
        historyListEl.appendChild(row);
      });
      applyUnreadBadges();
    }

    if (portalQueueSearchInput) {
      portalQueueSearchInput.addEventListener('input', function () {
        portalSearchQuery = portalQueueSearchInput.value;
        renderHistoryList();
      });
    }
    if (portalQueueStatusFilter) {
      portalQueueStatusFilter.addEventListener('change', function () {
        portalStatusFilter = portalQueueStatusFilter.value;
        renderHistoryList();
      });
    }
    if (portalQueueCategoryFilter) {
      portalQueueCategoryFilter.addEventListener('change', function () {
        portalCategoryFilter = portalQueueCategoryFilter.value;
        renderHistoryList();
      });
    }
    if (portalQueueClearFilters) {
      portalQueueClearFilters.addEventListener('click', function () {
        portalSearchQuery = ''; portalStatusFilter = ''; portalCategoryFilter = '';
        if (portalQueueSearchInput) portalQueueSearchInput.value = '';
        if (portalQueueStatusFilter) portalQueueStatusFilter.value = '';
        if (portalQueueCategoryFilter) portalQueueCategoryFilter.value = '';
        renderHistoryList();
      });
    }

    // Renders whatever `all` currently holds. Called once the initial fetch
    // resolves (and on failure, which lands on the empty state).
    function bootstrapPortal() {
      var empty = document.getElementById('portalEmpty');
      if (!all.length) {
        dash.style.display = 'none';
        if (empty) empty.style.display = 'block';
        renderHistoryList();
        return;
      }
      if (empty) empty.style.display = 'none';
      dash.style.display = '';
      // Prefer the ticket just created; otherwise the newest, since the API
      // already returns them ordered by created_at DESC.
      latest = all.filter(function (t) { return t.id === latestTicketId; })[0] || all[0];
      showTicketDetails(latest);
      renderHistoryList();
    }

    withDirectories(function () {
      if (!portalUser || !portalUser.id) { bootstrapPortal(); return; }
      fetchTickets({ user_id: portalUser.id }, function (rows) {
        all = rows;
        all.forEach(function (t) { knownStatuses[t.id] = t.status; });
        var countEl = document.getElementById('profileTicketCount');
        if (countEl) countEl.textContent = all.length;
        bootstrapPortal();
      }, function (err) {
        if (err && err.status === 401 && handleAuthExpired()) return;
        bootstrapPortal();
      });
    });

    // ---- Help bot (portal.html) ----
    // A scripted assistant with no AI service behind it: it matches what the
    // customer types against the rules below and answers from the tickets
    // this page already holds in `all`. Its only request is the SLA target
    // table. Anything it can't handle is pointed at a ticket or the agent
    // chat. To teach it something, edit the "Rules" lists.
    (function startHelpBot() {
      if (!portalUser || !portalUser.id) return;

      var TICKET_ID_RE = /\bTKT-\d{4}-\d{6}\b/i;
      var STATUS_HELP = {
        'Created': "We've received it and it's waiting to be assigned to an agent.",
        'Assigned': 'An agent has it and will pick it up shortly.',
        'In Progress': 'An agent is working on it now.',
        'Waiting': "The agent is waiting on a reply from you. Check the ticket's messages. The fix-time clock is paused until you answer.",
        'Escalated': "It's been passed to a specialist team.",
        'Resolved': 'The agent thinks it is fixed. Please confirm the fix, or reopen it if the problem is still there.',
        'Reopened': "You reopened it, so it's back with the support team on a fresh fix-time target.",
        'Closed': "It's finished. You can rate how we did."
      };
      // Filled from GET /api/tickets/sla-targets (utils/sla.js on the
      // server), so the bot never quotes targets the server doesn't enforce.
      // Stays null if the fetch fails; slaHelp() then leaves the table out.
      var slaTargets = null;
      fetch(API_BASE + '/api/tickets/sla-targets', { headers: authHeaders() })
        .then(function (response) { return response.ok ? response.json() : null; })
        .then(function (rows) { if (Array.isArray(rows)) slaTargets = rows; })
        .catch(function (err) { console.error('SLA targets load error:', err); });

      // " (fix 4 hrs)" for a priority, or '' until slaTargets loads.
      function slaText(priority) {
        var row = (slaTargets || []).filter(function (r) { return r.priority === priority; })[0];
        return row ? ' (fix ' + escapeHtml(row.resolution) + ')' : '';
      }

      // ---- Rules: edit these to change what the bot knows ----
      // `words` are matched as whole words or phrases, in lower case.
      // `answer` is HTML written here (never user input), so tags like
      // <strong> and <br> work; it can also be a function returning HTML when
      // the text depends on loaded data. `buttons` are links: { label, href }.

      // Fixed answers. The first rule whose words appear in the message wins.
      var FAQ_RULES = [
        {
          words: ['password', 'reset password', 'forgot password', 'sign in', 'sign-in', 'log in', 'login', 'verification code', 'sign-in code', 'login code', "can't get in"],
          answer: "There are no passwords. Each time you sign in, we email a 6-digit code to your account's email address. " +
            "If it doesn't arrive, check your spam folder or use <strong>Resend</strong> on the code screen. " +
            "Can't remember which email you used? Use <strong>Find my account</strong> on the sign-in page and our team will help."
        },
        {
          words: ['attach', 'attachment', 'attachments', 'upload', 'screenshot', 'screenshots', 'file', 'files', 'logs'],
          answer: "You can attach screenshots, logs or documents on the new ticket form, up to <strong>5MB per file</strong>. " +
            "You can also send files to the agent in a ticket's chat.",
          buttons: [{ label: 'Create a ticket', href: 'ticket.html' }]
        },
        {
          words: ['category', 'categories', 'which team', 'team', 'teams', 'department'],
          answer: 'Pick the category closest to the problem. It decides which team gets the ticket:<br>' +
            '<strong>Network</strong> (internet, Wi-Fi, VPN, connectivity): Network Support<br>' +
            '<strong>Application</strong> (software errors, products like Symphony or RiskFlow): Application Support<br>' +
            '<strong>Hardware</strong> (laptops, printers, devices): Infrastructure<br>' +
            '<strong>Access &amp; Identity</strong> (accounts, permissions, locked out): Access &amp; Identity',
          buttons: [{ label: 'Create a ticket', href: 'ticket.html' }]
        },
        {
          words: ['priority', 'priorities', 'which priority', 'how urgent'],
          answer: function () {
            return 'Choose the priority by how badly work is blocked:<br>' +
              '<strong>Critical</strong>: a service is down or many people are stopped' + slaText('Critical') + '<br>' +
              '<strong>High</strong>: you are blocked with no workaround' + slaText('High') + '<br>' +
              '<strong>Medium</strong>: it is slowing you down but there is a workaround' + slaText('Medium') + '<br>' +
              '<strong>Low</strong>: a question or minor issue' + slaText('Low');
          }
        }
      ];

      // Product knowledge. Until a product has a `summary` or `topics`, the
      // bot says it doesn't have that product's guides yet and offers an
      // agent instead. Each topic: { title, words, answer }.
      var PRODUCTS = [
        // From "Federation WhatsApp Starter Guide - Jul 2026" (12 pages) and
        // "Proposal: Symphony Chat Platform Integration with Local Ghanaian
        // SMS Gateway" (4 pages). Topics are checked in order, so the
        // specific ones come before the broad ones; the SMS overview is last
        // so a bare "sms" lands there.
        {
          name: 'Symphony',
          words: ['symphony', 'whatsapp', 'federation', 'sms', 'hubtel', 'mnotify', 'arkesel'],
          summary: '<strong>Symphony Messaging</strong> is a secure, compliant messaging platform for financial services. ' +
            'Its <strong>WhatsApp Federation</strong> channel lets you chat with external contacts on WhatsApp from Symphony, ' +
            'and a proposed <strong>Ghana SMS integration</strong> sends outbound 2FA codes and account updates to +233 numbers.',
          topics: [
            {
              title: 'Blocking contacts',
              words: ['block', 'blocking', 'unblock', 'spam', 'abuse', 'fraud', 'fraudulent'],
              answer: 'You can block a <strong>WhatsApp Direct</strong> contact to stop unwanted, disruptive or fraudulent messages:<br>' +
                "• <strong>Desktop:</strong> open the contact's profile and select <strong>Block</strong>.<br>" +
                "• <strong>Mobile:</strong> open the contact's profile, tap the <strong>More</strong> menu, then <strong>Block</strong>.<br>" +
                'Pick a reason (Spam, Abuse, Compliance or Other), add notes if you like, and confirm. ' +
                "Use <strong>Unblock</strong> on their profile to undo it. Colleagues aren't blocked, and shared group chats stay active."
            },
            {
              title: 'Contact has no WhatsApp',
              words: ['unavailable', 'account not found', 'no whatsapp', 'not on whatsapp', "doesn't have whatsapp", 'does not have whatsapp', 'grayed out', 'greyed out', 'remove contact', 'remove a contact', 'wrong number'],
              answer: "If you onboard someone who doesn't have WhatsApp, their card shows <strong>Unavailable</strong>, they're grayed out and can't be added to rooms, " +
                "and a message in the room says their WhatsApp account can't be found.<br>" +
                'To remove them, select <strong>Learn more</strong> on their card or in the warning, then <strong>Remove</strong>. ' +
                'Ask them to create a WhatsApp account or give you the correct number, then onboard them again.<br>' +
                'Admins can also remove Federation contacts with the <strong>Federation Channels</strong> app from the Symphony Marketplace.'
            },
            {
              title: 'WhatsApp voice calls',
              words: ['call', 'calls', 'calling', 'voice', 'recording', 'recorded', 'callback', 'call back'],
              answer: "Users entitled to <strong>WhatsApp Direct</strong> with the <strong>Enable calls</strong> permission can call contacts. " +
                'WhatsApp Voice is an add-on on request, at extra cost.<br>' +
                '1. In a chat with a WhatsApp Direct contact, select the <strong>WhatsApp Call</strong> button.<br>' +
                '2. The contact gets a call permission request and must allow it. In regions where business-initiated calls are not allowed, ' +
                'you request a callback instead and the contact taps <strong>Call on WhatsApp</strong>.<br>' +
                '3. The call starts as soon as the contact gives permission.<br>' +
                'If the <strong>Enable call recording</strong> permission is on, both sides are told the call is recorded.'
            },
            {
              title: 'QR code & profile link',
              words: ['qr', 'qr code', 'profile link', 'whatsapp link', 'scan', 'share my profile', 'unsolicited chat'],
              answer: 'WhatsApp contacts can reach you by scanning your profile QR code:<br>' +
                '• <strong>Mobile:</strong> three-dot menu → <strong>Profile</strong> → QR code icon (top right) → choose the WhatsApp QR code.<br>' +
                '• <strong>Desktop:</strong> your profile picture (bottom left) → <strong>View profile</strong> → <strong>WhatsApp</strong> tab. You can also copy the link and send it.<br>' +
                'With <strong>WhatsApp Direct</strong>, scanning opens a chat with your number. With <strong>WhatsApp Connect</strong> (and the <em>Allow unsolicited chat requests</em> add-on), ' +
                'the contact sends a prefilled message to a bot and gets a link to a chat with you.'
            },
            {
              title: "24-hour window (messages not showing)",
              words: ['24-hour', '24 hour', '24 hours', '24h', 'not receiving', 'not getting', 'not seeing', "can't see", 'view message', 'template', 'templates', 'inactive', 'queued', 'delayed'],
              answer: "WhatsApp has a <strong>24-hour rule</strong>: if a contact hasn't been active for over 24 hours, new messages don't show automatically. " +
                'They see a reminder and the queued messages appear once they send a message or tap <strong>View Message</strong>.<br>' +
                'Ask your TAM or SA about <strong>WhatsApp interactive message templates</strong>, which deliver immediately without the 24-hour limit.'
            },
            {
              title: 'Chats & group chats',
              words: ['group', 'groups', 'group chat', 'native group', 'one-to-one', 'start a chat', 'new chat', 'more than 8', 'request to join'],
              answer: '<strong>One-to-one:</strong> select <strong>+</strong> (New Chat), search for the contact by name (or phone number on mobile), and start the chat.<br>' +
                '<strong>Group chat:</strong> on desktop select <strong>+</strong> → <strong>Create WhatsApp Group Chat</strong>; on mobile, three-dot menu → <strong>Create group</strong> → WhatsApp. ' +
                'Add contacts (at least one WhatsApp contact), name the group and create it.<br>' +
                '• <strong>Create as native WhatsApp group</strong> (add-on) is limited to 8 WhatsApp contacts. Untick it for a standard chat with more.<br>' +
                '• In a native group, each WhatsApp contact gets an invite link, taps <strong>Request to join</strong>, and is accepted automatically.'
            },
            {
              title: 'Managing chat rooms',
              words: ['add members', 'add member', 'add someone', 'remove member', 'remove from', 'owner', 'owners', 'rename', 'room name', 'promote', 'demote', 'chat details', 'members'],
              answer: '• <strong>Add members:</strong> desktop: <strong>Add members</strong> at the top of the chat. Mobile: tap the chat header → <strong>Members</strong> → <strong>+</strong>.<br>' +
                '• <strong>Remove, promote or demote:</strong> desktop: three-dot menu → <strong>Chat details</strong> → <strong>Members</strong> → the member\'s menu. ' +
                'Mobile: press the member\'s name on the Members screen. Options: Make an owner, Remove as owner, Remove from conversation.<br>' +
                '• <strong>Rename:</strong> desktop: pencil icon by the room name. Mobile: chat header → <strong>Edit</strong>.'
            },
            {
              title: 'Editing contacts',
              words: ['edit', 'edit contact', 'update contact', 'change name', 'change email', 'change details', 'incomplete', 'incomplete contact', 'unknown number'],
              answer: "Users and admins can update a WhatsApp contact's name, company and email.<br>" +
                "• <strong>Desktop:</strong> open the contact's profile (from search, or the chat's Members panel → <strong>View profile</strong>), select <strong>Edit Contact</strong>, then <strong>Save</strong>.<br>" +
                "• <strong>Mobile:</strong> open the profile, tap <strong>More</strong> → <strong>Edit</strong>, then <strong>Save</strong>.<br>" +
                "When someone not in your contacts messages your WhatsApp Direct number, an <strong>incomplete contact</strong> and chat are created automatically. " +
                "Edit it the same way; the chat name updates too.<br>" +
                "Contact details are shared company-wide, so changes affect every Federation user."
            },
            {
              title: 'What the contact sees',
              words: ['onboarding message', 'invite', 'invitation', 'contact see', 'client see', 'tap continue', 'receive', 'join'],
              answer: 'Once you add a WhatsApp contact, they get an onboarding message from Symphony Messaging on WhatsApp:<br>' +
                '1. They tap <strong>Continue</strong> in the chat.<br>' +
                '2. Depending on the setup, they reply or tap to connect with you.<br>' +
                '3. They can then chat securely with you on WhatsApp.<br>' +
                'Message templates and flows can be customised.'
            },
            {
              title: 'Adding WhatsApp contacts',
              words: ['add', 'adding', 'add contact', 'add a contact', 'new contact', 'create contact', 'create a contact', 'onboard', 'bulk', 'connect bot', 'already onboarded', "doesn't match", 'does not match', 'mismatch', 'contacts app', 'vcard', 'default app', 'address book'],
              answer: '• <strong>Desktop:</strong> select <strong>+</strong> (Create) or Connections → <strong>Add contact</strong>, choose <strong>WhatsApp</strong>, fill in first name, last name, company, email and phone, tick <em>Create a chat</em> if you want one, then <strong>Add</strong> and <strong>Confirm</strong>.<br>' +
                '• <strong>Mobile:</strong> tap <strong>+</strong> → <strong>Add contact</strong> → WhatsApp, fill in the details (email optional) or pick from your address book, then <strong>Add</strong> and <strong>Confirm</strong>. ' +
                "You can also share a contact from your phone's Contacts app to Symphony Messaging.<br>" +
                '• <strong>In bulk:</strong> use the <strong>Connect Bot</strong> (ask your TAM to enable it; see the Connect Bot User Guide on Symphony Docs).<br>' +
                "If a colleague already onboarded the contact, use the <strong>same email and phone number</strong>. The app warns you if they don't match."
            },
            {
              title: 'WhatsApp Connect vs Direct',
              words: ['whatsapp connect', 'whatsapp direct', 'shared number', 'dedicated number', 'difference', 'entitlement', 'entitled', 'federation channels'],
              answer: 'One WhatsApp Federation channel covers both:<br>' +
                '• <strong>WhatsApp Connect</strong>: shared WhatsApp numbers. Supports native WhatsApp groups (add-on) and unsolicited chat requests via a bot (add-on).<br>' +
                '• <strong>WhatsApp Direct</strong>: a dedicated WhatsApp number per user. Supports voice calls (add-on), blocking contacts, and incomplete contacts from unknown numbers. ' +
                "Its chats don't appear in the ROOMS tab of the WhatsApp extension app.<br>" +
                'The <strong>Federation Channels</strong> app in the Symphony Marketplace handles admin actions such as removing a contact.'
            },
            {
              title: 'Ghana SMS: number format',
              words: ['number format', 'phone format', 'e.164', 'e164', '233', 'normalize', 'normalise', 'sanitize', 'sanitise', 'leading 0', 'leading zero', 'country code'],
              answer: 'The SMS Integration Bridge normalises Ghanaian numbers before calling the provider:<br>' +
                '• Strip spaces, dashes and the leading 0.<br>' +
                '• Add the country code <strong>233</strong> (or +233, depending on the provider).<br>' +
                '• Example: <strong>0244123456</strong> or <strong>+233 24 412 3456</strong> → <strong>233244123456</strong>'
            },
            {
              title: 'Ghana SMS: provider & Sender ID',
              words: ['hubtel', 'mnotify', 'arkesel', 'provider', 'providers', 'aggregator', 'contract', 'contracting', 'billing', 'credits', 'nca', 'dpc', 'regulatory', 'regulation', 'compliance', 'licence', 'license', 'sender id', 'sender name', 'mtn', 'telecel', 'airteltigo'],
              answer: '• <strong>Contract:</strong> the customer contracts directly with a local Ghanaian SMS provider (e.g. <strong>Hubtel</strong>, <strong>mNotify</strong> or <strong>Arkesel</strong>) that connects to MTN, Telecel and AT. ' +
                "Symphony is only the technical integration partner and doesn't resell SMS credits.<br>" +
                "• <strong>Compliance &amp; billing:</strong> the customer handles NCA and Data Protection Commission obligations, balances and volume tiers with the provider.<br>" +
                "• <strong>Sender ID:</strong> an alphanumeric ID of up to <strong>11 characters</strong> (e.g. SYM-2FA), registered through the provider under the customer's legal entity. " +
                "It usually needs a Business Registration Certificate, and stops messages being blocked as spam."
            },
            {
              title: 'Ghana SMS: security & rollout',
              words: ['masking', 'mask', 'rate limit', 'rate limiting', 'logs', 'logging', 'pii', 'firewall', 'timeline', 'how long', 'weeks', 'go live', 'rollout', 'implementation', 'testing'],
              answer: '<strong>Security:</strong><br>' +
                '• Outbound only, so no firewall changes for inbound internet traffic.<br>' +
                '• Logs mask codes and personal data (e.g. "Sent 2FA to 233244XXXXXX").<br>' +
                '• Rate limiting in the middleware prevents SMS spam and unexpected bills.<br>' +
                '<strong>Rollout (4 weeks):</strong><br>' +
                '1. Week 1: choose the provider, open the account, request the Sender ID.<br>' +
                '2. Week 2: build the Symphony bot and middleware.<br>' +
                '3. Week 3: end-to-end testing on MTN, Telecel and AT test numbers.<br>' +
                '4. Week 4: move to production and hand over to operations.'
            },
            {
              title: 'Ghana SMS: how it works',
              words: ['sms', 'text message', 'text messages', '2fa', 'otp', 'account update', 'account updates', 'middleware', 'bridge', 'outbound', 'inbound', 'reply', 'two-way', 'payload', 'flow'],
              answer: 'The proposed integration is <strong>outbound only</strong> (no incoming SMS), for 2FA codes and account updates to Ghanaian (+233) numbers:<br>' +
                '1. A workflow or security event in Symphony triggers a 2FA request or account update.<br>' +
                '2. A custom <strong>Symphony bot</strong> (BDK/REST API) catches the event.<br>' +
                '3. The bot POSTs the phone number and message to the internal <strong>SMS Integration Bridge</strong>.<br>' +
                "4. The bridge normalises the number and sends it over HTTPS (API key / Bearer token) to the customer's Ghanaian SMS provider, which delivers it through MTN, Telecel or AT."
            }
          ]
        },
        // From "Riskflow Calibre Treasury Management Application Hardware
        // Architecture" (2 pages). Topics are checked in order, so the
        // specific ones come before the general overview words.
        {
          name: 'RiskFlow',
          words: ['riskflow', 'risk flow', 'risk-flow', 'calibre', 'treasury management'],
          summary: '<strong>RiskFlow Calibre Treasury Management</strong> handles cash management, liquidity planning and FX trading, ' +
            'and connects securely to your Core Banking system. It runs on a secure multi-tier setup: firewalls, load balancers, ' +
            'application servers and a database cluster.',
          topics: [
            {
              title: 'Server setup & DR site',
              words: ['how many servers', 'server requirements', 'hardware requirements', 'requirements', 'dr', 'disaster recovery', 'recovery site', 'data recovery', 'co-habit', 'cohabit', 'same server', 'linux', 'docker', 'virtual', 'physical', 'vm'],
              answer: '• <strong>Treasury Web Server 1</strong> and <strong>Treasury App Server 1</strong> can share the same physical or virtual server.<br>' +
                '• <strong>Treasury Web Server 2</strong> and <strong>Treasury App Server 2</strong> can share the same physical or virtual server at the Data Recovery site.<br>' +
                '• The <strong>Linux service</strong> can run as a Docker service on Treasury App Server 1 if that server is physical. If App Server 1 is virtual, the Linux server has to be a separate server.'
            },
            {
              title: 'Firewalls & load balancers',
              words: ['firewall', 'firewalls', 'waf', 'web application firewall', 'load balancer', 'load balancers', 'load balancing', 'presentation layer', 'dmz'],
              answer: '• <strong>Web Application Firewall (WAF)</strong>: inspects incoming internet and intranet traffic for malicious attacks.<br>' +
                '• <strong>Load balancers</strong>: spread user requests evenly across the web and presentation servers.<br>' +
                '• <strong>Internal firewall</strong>: sits between the web servers and the app servers, separating the DMZ from the secure internal bank network.'
            },
            {
              title: 'Security & HSM',
              words: ['hsm', 'hardware security module', 'security', 'secure', 'keys', 'cryptographic', 'encryption', 'signing', 'certificates'],
              answer: '• <strong>Hardware Security Module (HSM)</strong>: stores the cryptographic keys and handles secure message signing for financial transactions. It connects to the Treasury App Servers.<br>' +
                '• <strong>Internal firewalls</strong>: separate the DMZ from the secure internal bank network.<br>' +
                '• <strong>WAF</strong>: screens incoming traffic for attacks before it reaches the application.'
            },
            {
              title: 'Core Banking integration',
              words: ['core banking', 't24', 'esb', 'enterprise service bus', 'api gateway', 'api', 'apis', 'integration', 'integrate', 'interface', 'mq', 'iso 8583', 'iso 20022', '8583', '20022', 'asp.net'],
              answer: '• <strong>Enterprise Service Bus (ESB) / API Gateway</strong> (ASP.NET API): translates and routes messages between Calibre and the Core Banking application.<br>' +
                '• <strong>Core Banking interface</strong>: connects securely over dedicated enterprise links (MQ, ISO 8583/20022, or secure APIs) directly to the Core Banking host. The Core Banking system shown is <strong>T24</strong>.'
            },
            {
              title: 'Database',
              words: ['database', 'databases', 'db', 'sql', 'mssql', 'sql server', 'cluster', 'high availability', 'ha', 'active-passive', 'active-active', 'data layer'],
              answer: 'The <strong>Treasury Database Cluster</strong> runs on <strong>MS SQL</strong>. It stores active transactional data, deal captures and user session states, ' +
                'with high availability (active-passive or active-active).'
            },
            {
              title: 'Web & application servers',
              words: ['web server', 'web servers', 'app server', 'app servers', 'application server', 'application servers', 'iis', 'treasury server', 'application layer', 'cash management', 'liquidity', 'fx', 'trading'],
              answer: '• <strong>Treasury Web Servers 1 &amp; 2</strong> (IIS): serve the web interface that internal users and branches use from their workstations.<br>' +
                '• <strong>Treasury App Servers 1 &amp; 2</strong>: process the cash management, liquidity planning and FX trading logic.'
            },
            {
              title: 'Architecture overview',
              words: ['architecture', 'layers', 'tiers', 'multi-tier', 'multitier', 'diagram', 'overview', 'infrastructure', 'how is it set up', 'how does it work'],
              answer: 'From the users down, each layer talks only to the next:<br>' +
                '1. <strong>Internal users / branches</strong>: web interface on their workstations<br>' +
                '2. <strong>Web Application Firewall</strong><br>' +
                '3. <strong>Load balancers</strong> (presentation layer)<br>' +
                '4. <strong>Treasury Web Servers 1 &amp; 2</strong> (IIS)<br>' +
                '5. <strong>Internal firewall</strong><br>' +
                '6. <strong>Treasury App Servers 1 &amp; 2</strong>, linked to the <strong>HSM</strong><br>' +
                '7. <strong>ESB / API Gateway</strong> (ASP.NET API, integration &amp; security layer)<br>' +
                '8. <strong>Treasury DB cluster</strong> (MS SQL), linked to the <strong>Core Banking system</strong> (T24)'
            }
          ]
        }
      ];

      // Words that mean "this is an emergency": the bot steers them to a
      // Critical ticket (or the agent on an existing one).
      var URGENT_WORDS = ['urgent', 'outage', 'emergency', 'asap', 'is down', 'went down', 'everyone', 'nobody can', 'no one can', 'production'];

      // Words for filtering the customer's own tickets ("any escalated
      // tickets?", "show my high priority network tickets").
      var STATUS_WORDS = { 'escalated': 'Escalated', 'waiting': 'Waiting', 'resolved': 'Resolved', 'closed': 'Closed', 'reopened': 'Reopened', 'in progress': 'In Progress', 'assigned': 'Assigned' };
      var PRIORITY_WORDS = { 'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low' };
      var CATEGORY_WORDS = { 'network': 'Network', 'application': 'Application', 'hardware': 'Hardware', 'access': 'Access & Identity' };
      var LIST_WORDS = ['which', 'any', 'show', 'list', 'how many', 'do i have', 'tickets'];

      document.body.classList.add('has-helpbot');

      var launcher = document.createElement('button');
      launcher.type = 'button';
      launcher.className = 'helpbot-launcher';
      launcher.setAttribute('aria-label', 'Open the help assistant');
      launcher.setAttribute('aria-expanded', 'false');
      launcher.innerHTML = '<span aria-hidden="true">?</span>';

      var panel = document.createElement('div');
      panel.className = 'helpbot-panel';
      panel.setAttribute('role', 'dialog');
      panel.setAttribute('aria-label', 'Help assistant');
      panel.hidden = true;
      panel.innerHTML =
        '<div class="helpbot-head">' +
          '<div><p class="helpbot-title">Help assistant</p><p class="helpbot-sub">Automated · answers from your tickets</p></div>' +
          '<button type="button" class="helpbot-close" aria-label="Close the help assistant">✕</button>' +
        '</div>' +
        '<div class="helpbot-log" aria-live="polite"></div>' +
        '<form class="helpbot-form">' +
          '<input type="text" class="helpbot-input" maxlength="300" autocomplete="off" placeholder="Ask about your tickets…" aria-label="Message the help assistant">' +
          '<button type="submit" class="helpbot-send">Send</button>' +
        '</form>';

      document.body.appendChild(panel);
      document.body.appendChild(launcher);

      var log = panel.querySelector('.helpbot-log');
      var form = panel.querySelector('.helpbot-form');
      var input = panel.querySelector('.helpbot-input');
      var greeted = false;

      function openBot() {
        panel.hidden = false;
        launcher.setAttribute('aria-expanded', 'true');
        launcher.classList.add('open');
        if (!greeted) { greeted = true; greet(); }
        input.focus();
      }
      function closeBot() {
        panel.hidden = true;
        launcher.setAttribute('aria-expanded', 'false');
        launcher.classList.remove('open');
        launcher.focus();
      }
      launcher.addEventListener('click', function () { panel.hidden ? openBot() : closeBot(); });
      panel.querySelector('.helpbot-close').addEventListener('click', closeBot);
      panel.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeBot(); });

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var text = input.value.trim();
        if (!text) return;
        input.value = '';
        handle(text);
      });

      // ---- Rendering ----
      // Bot messages are HTML strings; every value that came from a ticket or
      // the profile goes through escapeHtml() where it's concatenated in.
      function addMessage(who, html) {
        var el = document.createElement('div');
        el.className = 'helpbot-msg helpbot-' + who;
        el.innerHTML = html;
        log.appendChild(el);
        log.scrollTop = log.scrollHeight;
      }

      // Each choice is { label, run } (answered in the chat) or { label, href }
      // (navigates away).
      function addChoices(choices) {
        var row = document.createElement('div');
        row.className = 'helpbot-choices';
        choices.forEach(function (c) {
          var el;
          if (c.href) {
            el = document.createElement('a');
            el.href = c.href;
          } else {
            el = document.createElement('button');
            el.type = 'button';
            el.addEventListener('click', function () { handle(c.label, c.run); });
          }
          el.className = 'helpbot-chip';
          el.textContent = c.label;
          row.appendChild(el);
        });
        log.appendChild(row);
        log.scrollTop = log.scrollHeight;
      }

      function reply(html, choices) {
        addMessage('bot', html);
        if (choices && choices.length) addChoices(choices);
      }

      // Echoes what the customer said, clears the old choice buttons so only
      // the latest set is clickable, then answers after a short pause.
      function handle(text, run) {
        log.querySelectorAll('.helpbot-choices').forEach(function (row) { row.remove(); });
        addMessage('user', escapeHtml(text));
        setTimeout(function () { (run || answer)(text); }, 300);
      }

      // ---- Ticket helpers ----
      function isOpen(t) { return t.status !== 'Resolved' && t.status !== 'Closed'; }
      function findTicket(id) { return all.filter(function (t) { return t.id.toUpperCase() === id; })[0]; }
      function chatLink(t) { return 'ticket-chat.html?ticket=' + encodeURIComponent(t.id) + '&role=customer'; }
      function shortSubject(t) { return t.subject.length > 26 ? t.subject.slice(0, 25) + '…' : t.subject; }
      function ticketLine(t) { return '<strong>' + escapeHtml(t.id) + '</strong> · ' + escapeHtml(t.subject) + ' (' + escapeHtml(t.status) + ')'; }
      function ticketChoice(t) { return { label: shortSubject(t) + ' · ' + t.status, run: function () { describeTicket(t.id.toUpperCase()); } }; }

      // Opens the ticket in the page's detail card and scrolls to `targetId`
      // (or the card itself), so the customer can use the real buttons there.
      function showOnPage(t, targetId) {
        showTicketDetails(t);
        var target = (targetId && document.getElementById(targetId)) || dash;
        target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      function menuChoices() {
        return [
          { label: 'My tickets', run: summarize },
          { label: 'Talk to an agent', run: contactAgent },
          { label: 'Report a new problem', run: newTicket },
          { label: 'Our products', run: productsMenu },
          { label: 'How long will it take?', run: slaHelp },
          { label: 'What do the statuses mean?', run: function () { statusHelp(''); } }
        ];
      }

      function linkButtons(buttons) {
        return (buttons || []).map(function (b) { return { label: b.label, href: b.href }; });
      }

      function productFor(q) {
        return PRODUCTS.filter(function (p) { return has(q, p.words); })[0];
      }

      // ---- Answers ----
      function greet() {
        var first = (portalUser.name || '').trim().split(/\s+/)[0];
        var html = 'Hi' + (first ? ' ' + escapeHtml(first) : '') + ". I'm an automated assistant. I can look up your tickets and point you to the right place.";
        var waiting = all.filter(function (t) { return t.status === 'Resolved' || t.status === 'Waiting'; });
        if (waiting.length) {
          html += '<br><br><strong>' + waiting.length + (waiting.length === 1 ? ' ticket is' : ' tickets are') + ' waiting on you:</strong><br>' +
            waiting.map(ticketLine).join('<br>');
        }
        reply(html, menuChoices());
      }

      function summarize() {
        if (!all.length) {
          return reply("You don't have any tickets yet.", [{ label: 'Report a new problem', run: newTicket }]);
        }
        var open = all.filter(isOpen);
        var resolved = all.filter(function (t) { return t.status === 'Resolved'; });
        var closed = all.filter(function (t) { return t.status === 'Closed'; });
        var html = 'You have <strong>' + all.length + '</strong> ticket' + (all.length === 1 ? '' : 's') + ': ' +
          open.length + ' open, ' + resolved.length + ' resolved (waiting for you to confirm), ' + closed.length + ' closed.';
        if (open.length) html += '<br><br>Open:<br>' + open.slice(0, 5).map(ticketLine).join('<br>');
        if (open.length > 5) html += '<br>…and ' + (open.length - 5) + ' more in "Your tickets" below.';
        var pick = open.concat(resolved).slice(0, 4);
        reply(html + (pick.length ? '<br><br>Pick one for details:' : ''), pick.map(ticketChoice));
      }

      function describeTicket(id) {
        var t = findTicket(id);
        if (!t) {
          return reply("I can't find <strong>" + escapeHtml(id) + '</strong> among your tickets. Check the number, or pick one of yours:',
            all.slice(0, 4).map(ticketChoice));
        }
        var now = Date.now();
        var html = ticketLine(t) + '<br>' + escapeHtml(STATUS_HELP[t.status] || '') +
          '<br><br>Priority: ' + escapeHtml(t.priority) +
          '<br>Team: ' + escapeHtml(t.team || '—') +
          '<br>Agent: ' + escapeHtml(t.assignedAgent || 'not assigned yet');
        if (isOpen(t) && t.resolutionDueAt) {
          var alertInfo = slaAlert(t, now);
          if (t.slaPausedAt) html += '<br>Fix-time target: paused while we wait on you.';
          else html += '<br>Fix-time target: ' + escapeHtml(new Date(t.resolutionDueAt).toLocaleString()) + ' (' + escapeHtml(fmtSlaRelative(new Date(t.resolutionDueAt).getTime(), now)) + ')';
          if (alertInfo && alertInfo.level === 'breached') html += "<br><strong>This one is past its target.</strong> Sending the agent a message will flag it.";
        }

        var choices = [];
        if (t.status === 'Resolved') choices.push({ label: 'Confirm or reopen it', run: function () { showOnPage(t, 'resolutionRow'); reply('It\'s open on the page. Use <strong>Confirm fix ✓</strong> if it works, or <strong>Reopen ticket</strong> if it doesn\'t.'); } });
        if (t.status === 'Closed' && !t.csat) choices.push({ label: 'Rate this ticket', run: function () { showOnPage(t, 'csatPanel'); reply('The rating form is open on the page.'); } });
        if (t.status !== 'Closed') choices.push({ label: 'Message the agent', href: chatLink(t) });
        choices.push({ label: 'Show it on the page', run: function () { showOnPage(t); reply("Done, it's open on the page."); } });
        reply(html, choices);
      }

      function contactAgent() {
        var open = all.filter(function (t) { return t.status !== 'Closed'; });
        if (!open.length) {
          return reply("You don't have an open ticket to message on. Create one and an agent will reply on it.",
            [{ label: 'Create a ticket', href: 'ticket.html' }]);
        }
        reply('To talk to a person, message the agent on the ticket. Which one is it about?',
          open.slice(0, 4).map(function (t) { return { label: shortSubject(t), href: chatLink(t) }; })
            .concat([{ label: "It's something new", href: 'ticket.html' }]));
      }

      function newTicket() {
        reply('Report it with the new ticket form. Pick the closest category (Network, Application, Hardware, or Access &amp; Identity) and a priority, and describe what happened. Attach screenshots if you have them.',
          [{ label: 'Create a ticket', href: 'ticket.html' }]);
      }

      function reopenHelp() {
        var resolved = all.filter(function (t) { return t.status === 'Resolved'; });
        var html = 'You can reopen a ticket while it\'s <strong>Resolved</strong>. Open it and press <strong>Reopen ticket</strong>. ' +
          'A <strong>Closed</strong> ticket can\'t be reopened, so create a new one and mention the old ticket number.';
        var choices = resolved.slice(0, 4).map(function (t) {
          return { label: 'Reopen ' + shortSubject(t), run: function () { showOnPage(t, 'resolutionRow'); reply("It's open on the page. Press <strong>Reopen ticket</strong>."); } };
        });
        choices.push({ label: 'Create a ticket', href: 'ticket.html' });
        reply(html, choices);
      }

      function closeHelp() {
        var resolved = all.filter(function (t) { return t.status === 'Resolved'; });
        var unrated = all.filter(function (t) { return t.status === 'Closed' && !t.csat; });
        if (!resolved.length && !unrated.length) {
          return reply("Nothing is waiting for you to confirm or rate right now. Once an agent marks a ticket Resolved, you'll be able to confirm the fix and then rate it.");
        }
        var choices = resolved.slice(0, 3).map(function (t) {
          return { label: 'Confirm ' + shortSubject(t), run: function () { showOnPage(t, 'resolutionRow'); reply("It's open on the page. Press <strong>Confirm fix ✓</strong>."); } };
        }).concat(unrated.slice(0, 3).map(function (t) {
          return { label: 'Rate ' + shortSubject(t), run: function () { showOnPage(t, 'csatPanel'); reply('The rating form is open on the page.'); } };
        }));
        reply('Confirming a fix closes the ticket. After that you can rate how we did.', choices);
      }

      function slaHelp() {
        var html = 'Every ticket has a fix target, set by its priority.<br>' +
          (slaTargets
            ? slaTargets.map(function (r) {
                return '<strong>' + escapeHtml(r.priority) + '</strong>: fix ' + escapeHtml(r.resolution);
              }).join('<br>')
            : "I couldn't load the target table just now, but each ticket's own target is shown when you pick it.") +
          '<br><br>The clocks run around the clock. The fix clock pauses while a ticket is Waiting on you, and while it\'s Resolved and waiting for you to confirm or reopen.';
        var open = all.filter(isOpen);
        reply(html + (open.length ? '<br><br>Want the target for one of yours?' : ''), open.slice(0, 4).map(ticketChoice));
      }

      function statusHelp(q) {
        // Whole words, so "unassigned" doesn't pick up Assigned.
        var named = Object.keys(STATUS_HELP).filter(function (s) { return has(q, [s.toLowerCase()]); });
        var list = named.length ? named : Object.keys(STATUS_HELP);
        reply(list.map(function (s) { return '<strong>' + s + '</strong>: ' + escapeHtml(STATUS_HELP[s]); }).join('<br>'));
      }

      function accountHelp() {
        reply('Your account:<br>Name: ' + escapeHtml(portalUser.name) +
          '<br>Email: ' + escapeHtml(portalUser.email) +
          '<br>ID: ' + escapeHtml(portalUser.id) +
          "<br><br>You can't change these from the portal yet. Message an agent on any ticket and they'll update them for you.",
          [{ label: 'Talk to an agent', run: contactAgent }]);
      }

      function signOutHelp() {
        reply('Use <strong>Logout</strong> at the top right to sign out here. <strong>Sign out all devices</strong> ends your session everywhere, including this browser. Use it if you signed in on a shared or lost device.');
      }

      function productsMenu() {
        reply('These are the products we support. Pick one to see what I can help with:', PRODUCTS.map(function (p) {
          return { label: p.name, run: function () { productHelp(p, ''); } };
        }));
      }

      function productHelp(p, q) {
        var report = { label: 'Report a ' + p.name + ' problem', href: 'ticket.html?category=Application&service=' + encodeURIComponent(p.name) };
        var related = all.filter(function (t) { return isOpen(t) && t.service && has(t.service.toLowerCase(), p.words); });
        var relatedHtml = related.length
          ? '<br><br>Your open ' + p.name + ' tickets:<br>' + related.slice(0, 3).map(ticketLine).join('<br>')
          : '';
        var relatedChoices = related.slice(0, 2).map(ticketChoice);

        if (!p.summary && !p.topics.length) {
          return reply("I don't have " + p.name + ' guides yet. An agent can answer your question, or you can report a problem.' + relatedHtml,
            relatedChoices.concat([{ label: 'Talk to an agent', run: contactAgent }, report]));
        }

        var topic = p.topics.filter(function (tp) { return has(q, tp.words); })[0];
        if (topic) {
          return reply('<strong>' + p.name + ': ' + topic.title + '</strong><br>' + topic.answer + relatedHtml,
            relatedChoices.concat([report]));
        }

        var topicChoices = p.topics.map(function (tp) {
          return { label: tp.title, run: function () { reply('<strong>' + p.name + ': ' + tp.title + '</strong><br>' + tp.answer, [report]); } };
        });
        reply((p.summary || p.name) + (p.topics.length ? '<br><br>What do you need help with?' : '') + relatedHtml,
          topicChoices.concat(relatedChoices, [report]));
      }

      function urgentHelp(q) {
        var p = productFor(q);
        var href = 'ticket.html?priority=Critical' + (p ? '&category=Application&service=' + encodeURIComponent(p.name) : '');
        var open = all.filter(function (t) { return t.status !== 'Closed'; });
        reply("If a service is down or it's stopping many people from working, raise a <strong>Critical</strong> ticket" + slaText('Critical') + '.' +
          (open.length ? "<br><br>If it's about a ticket you already have, message the agent there instead so it isn't split in two." : ''),
          [{ label: 'Create a Critical ticket', href: href }].concat(open.slice(0, 3).map(function (t) {
            return { label: 'Message on ' + shortSubject(t), href: chatLink(t) };
          })));
      }

      // Returns false when the message has no filter words, so answer() can
      // move on to the next topic.
      function ticketQuery(q) {
        if (!has(q, LIST_WORDS)) return false;
        var pick = function (map) { return Object.keys(map).filter(function (w) { return has(q, [w]); }).map(function (w) { return map[w]; }); };
        var statuses = pick(STATUS_WORDS);
        var priorities = pick(PRIORITY_WORDS);
        var categories = pick(CATEGORY_WORDS);
        var wantOpen = has(q, ['open']);
        if (!statuses.length && !priorities.length && !categories.length && !wantOpen) return false;

        var matches = all.filter(function (t) {
          if (statuses.length && statuses.indexOf(t.status) === -1) return false;
          if (priorities.length && priorities.indexOf(t.priority) === -1) return false;
          if (categories.length && categories.indexOf(t.category) === -1) return false;
          if (wantOpen && !statuses.length && !isOpen(t)) return false;
          return true;
        });
        var label = escapeHtml(statuses.concat(priorities.map(function (p) { return p + ' priority'; }), categories, wantOpen && !statuses.length ? ['open'] : []).join(', '));
        if (!matches.length) {
          reply("You don't have any tickets matching <strong>" + label + '</strong>.', [{ label: 'All my tickets', run: summarize }]);
          return true;
        }
        reply(matches.length + ' ticket' + (matches.length === 1 ? '' : 's') + ' matching <strong>' + label + '</strong>:<br>' +
          matches.slice(0, 6).map(ticketLine).join('<br>') +
          (matches.length > 6 ? '<br>…and ' + (matches.length - 6) + ' more in "Your tickets" below.' : ''),
          matches.slice(0, 4).map(ticketChoice));
        return true;
      }

      function fallback() {
        reply("Sorry, I'm a simple assistant and didn't catch that. Try a ticket number (like TKT-2026-123456), or pick a topic:", menuChoices());
      }

      // Whole-word match, so "hi" doesn't fire on "this".
      function has(q, words) {
        return words.some(function (w) {
          return new RegExp('\\b' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(q);
        });
      }

      // Topic order matters: the specific ones ("reopen", "what does waiting
      // mean") are checked before the broad ones ("open", "ticket").
      function answer(text) {
        var q = text.toLowerCase();
        var idMatch = text.match(TICKET_ID_RE);
        if (idMatch) return describeTicket(idMatch[0].toUpperCase());
        if (has(q, URGENT_WORDS)) return urgentHelp(q);
        if (has(q, ['sign out', 'log out', 'logout', 'signout', 'devices'])) return signOutHelp();
        if (has(q, ['reopen', 'not fixed', 'still broken', 'came back', 'happening again'])) return reopenHelp();
        if (has(q, ['mean', 'means', 'meaning', 'statuses'])) return statusHelp(q);
        var product = productFor(q);
        if (product) return productHelp(product, q);
        if (has(q, ['product', 'products'])) return productsMenu();
        if (has(q, ['sla', 'how long', 'when will', 'eta', 'deadline', 'due', 'target', 'overdue', 'late'])) return slaHelp();
        if (ticketQuery(q)) return;
        var faq = FAQ_RULES.filter(function (r) { return has(q, r.words); })[0];
        if (faq) return reply(typeof faq.answer === 'function' ? faq.answer() : faq.answer, linkButtons(faq.buttons));
        if (has(q, ['confirm', 'rate', 'rating', 'feedback', 'stars', 'close'])) return closeHelp();
        if (has(q, ['human', 'agent', 'person', 'someone', 'speak', 'talk', 'message', 'chat', 'contact', 'call'])) return contactAgent();
        if (has(q, ['status', 'my tickets', 'my ticket', 'progress', 'update', 'open tickets'])) return summarize();
        if (has(q, ['new', 'create', 'raise', 'report', 'submit', 'problem', 'issue', 'broken', 'not working', 'error', 'help me'])) return newTicket();
        if (has(q, ['ticket', 'tickets'])) return summarize();
        if (has(q, ['email', 'account', 'name', 'phone', 'profile', 'details', 'department'])) return accountHelp();
        if (has(q, ['thank', 'thanks', 'cheers'])) return reply("You're welcome. Anything else?", menuChoices());
        if (has(q, ['hi', 'hello', 'hey', 'morning', 'afternoon', 'evening', 'menu', 'help', 'start'])) return reply('What can I help with?', menuChoices());
        fallback();
      }
    })();

    // ---- FR-4: live notifications on status change ----
    // Status changes happen on the agent dashboard (a different tab/window),
    // so this tab needs to notice the shared localStorage record changing
    // and refresh in place instead of requiring the customer to reload.

    function showStatusToast(ticket, fromStatus, toStatus) {
      var wrap = document.getElementById('statusToastWrap');
      if (!wrap) return;
      var toast = document.createElement('div');
      toast.className = 'status-toast';
      toast.innerHTML =
        '<div class="ic">✓</div>' +
        '<div class="toast-body">' +
          '<p class="toast-title">' + escapeHtml(ticket.id) + '</p>' +
          '<p class="toast-sub">' + (ticket.subject ? escapeHtml(ticket.subject) + ' — ' : '') +
            'now <strong>' + escapeHtml(toStatus) + '</strong> (was ' + escapeHtml(fromStatus || 'Created') + ')</p>' +
        '</div>' +
        '<button type="button" class="toast-close" aria-label="Dismiss notification">✕</button>';
      wrap.appendChild(toast);

      function dismiss() {
        toast.classList.add('leaving');
        setTimeout(function () { toast.remove(); }, 280);
      }
      toast.querySelector('.toast-close').addEventListener('click', dismiss);
      setTimeout(dismiss, 6000);
    }

    function pulseStatusBadge() {
      var badge = document.getElementById('dashStatusBadge');
      if (!badge) return;
      badge.classList.remove('pulse');
      void badge.offsetWidth; // restart the animation if it's already mid-pulse
      badge.classList.add('pulse');
    }

    // Takes a freshly fetched (already normalized) ticket list, diffs it
    // against what this tab last knew, refreshes the dashboard/history in
    // place, and toasts every ticket whose status actually moved.
    function applyRemoteTicketUpdate(updated) {
      if (!updated || !updated.length) return;

      var changedList = [];
      updated.forEach(function (t) {
        var prevStatus = knownStatuses[t.id];
        if (prevStatus !== undefined && prevStatus !== t.status) {
          changedList.push({ ticket: t, from: prevStatus, to: t.status });
        }
        knownStatuses[t.id] = t.status;
      });

      if (!changedList.length) return;

      all = updated;
      if (latest) {
        var freshLatest = all.filter(function (x) { return x.id === latest.id; })[0];
        if (freshLatest) latest = freshLatest;
      }
      // Re-showing the currently open ticket also re-syncs every history row's
      // status pill/class against the fresh `all` array (see showTicketDetails).
      if (currentTicketId) {
        var openTicket = all.filter(function (x) { return x.id === currentTicketId; })[0];
        if (openTicket) showTicketDetails(openTicket);
      }

      changedList.forEach(function (c) {
        showStatusToast(c.ticket, c.from, c.to);
        if (c.ticket.id === currentTicketId) pulseStatusBadge();
      });
    }

    // The `storage` listener that used to drive this is gone: tickets no longer
    // live in localStorage, so that event will never fire for them again. The
    // poll that was previously just a fallback is now the sole live-update
    // path — it refetches this user's tickets and feeds the same diff logic,
    // which stays a no-op until a status actually moves.
    setInterval(function () {
      if (!portalUser || !portalUser.id) return;
      fetchTickets({ user_id: portalUser.id }, applyRemoteTicketUpdate);
    }, 4000);
  }

  // ---- Agent queue (agent-dashboard.html): stats + filterable list + ticket actions ----
  var agentQueue = document.getElementById('agentQueue');
  if (agentQueue) {
    var agent = readSession('docketAgent');
    if (!agent) {
      window.location.href = 'agent-login.html';
      return;
    }

    // Agent profile (sidebar + topbar chip)
    var agentInitials = agent.name.trim().split(/\s+/).map(function (p) { return p[0]; }).slice(0, 2).join('').toUpperCase() || '?';
    document.getElementById('agentInitials').textContent = agentInitials;
    document.getElementById('agentName').textContent = agent.name;
    document.getElementById('agentId').textContent = agent.id;
    document.getElementById('agentEmailDisplay').textContent = agent.email;
    document.getElementById('agentChipInitials').textContent = agentInitials;
    document.getElementById('agentChipName').textContent = agent.name.split(' ')[0];

    function agentSignOut() {
      clearSession('docketAgent');
      window.location.href = 'agent-login.html';
    }
    document.getElementById('agentLogoutBtn').addEventListener('click', agentSignOut);
    wireSignOutEverywhere('agentSignOutAllBtn', agentSignOut);

    // Tickets are fetched from the API at the bottom of this block; the old
    // localStorage read (and the backfill defaults it needed for records
    // predating the status/assignment fields) is gone, since every row now
    // comes out of the database with those columns already populated.
    var tickets = [];

    var currentFilter = 'All';
    var searchQuery = '';
    var statusFilter = '';
    var categoryFilter = '';
    var dateFilter = '';
    var selectedId = null; // set once the fetch below resolves

    function statusClass(status) {
      if (status === 'Resolved') return 'status-resolved';
      if (status === 'Closed') return 'status-closed';
      if (status === 'Reopened') return 'status-reopened';
      if (status === 'In Progress') return 'status-progress';
      if (status === 'Waiting') return 'status-waiting';
      if (status === 'Escalated') return 'status-escalated';
      return '';
    }

    // Closed tickets are done, same as Resolved, for queue-health purposes.
    // Reopened tickets are back in the open pile until an agent resolves them again.
    function isOpenStatus(status) { return status !== 'Resolved' && status !== 'Closed'; }

    // ---- Ticket status state machine ----
    // Each key is a status an agent can act on; the value lists every status
    // it's allowed to move to next, with the button label to show for that move.
    // Anything not listed here (e.g. from Resolved/Closed) has no agent-facing
    // action — those only change via the customer's confirm/reopen on the portal.
    var STATUS_TRANSITIONS = {
      // No entry for 'Created': a ticket must be assigned to an agent (via
      // "Assign to me") before any status action becomes available.
      'Assigned': [
        { to: 'In Progress', label: 'Start progress' }
      ],
      'In Progress': [
        { to: 'Waiting', label: 'Mark waiting on customer' },
        { to: 'Escalated', label: 'Escalate' },
        { to: 'Resolved', label: 'Mark resolved' }
      ],
      'Waiting': [
        { to: 'In Progress', label: 'Resume progress' }
      ],
      'Escalated': [
        { to: 'In Progress', label: 'Resume progress' }
      ],
      'Reopened': [
        { to: 'In Progress', label: 'Resume progress' }
      ]
    };

    // True only if `to` is one of the moves STATUS_TRANSITIONS allows from `from`.
    // This is the single gate everything else in the agent view goes through, so
    // there's no path in the UI that can set a status out of sequence.
    function canTransition(from, to) {
      var moves = STATUS_TRANSITIONS[from] || [];
      return moves.some(function (m) { return m.to === to; });
    }

    // A refused update (409) carries the ticket as it is now: show that in
    // place of the stale copy and say why nothing happened. False for any
    // other error, which the caller reports as before.
    function showLatestAgentTicket(err) {
      if (!err || !err.latest) return false;
      replaceTicketIn(tickets, err.latest);
      agentKnownSignature[err.latest.id] = ticketSignature(err.latest);
      closePanels();
      renderStats(); renderDetail(); renderList();
      alert(err.message);
      return true;
    }

    function changeStatus(t, toStatus) {
      if (!isMine(t)) return;
      if (!canTransition(t.status, toStatus)) return;
      changeTicketStatus(t, { status: toStatus }, function (updated) {
        replaceTicketIn(tickets, updated);
        agentKnownSignature[updated.id] = ticketSignature(updated);
        renderStats(); renderDetail(); renderList();
      }, function (err) {
        if (showLatestAgentTicket(err)) return;
        alert(err.message || 'Unable to update the ticket status.');
      });
    }

    // Only the agent a ticket is currently assigned to may move its status,
    // escalate it, or resolve it. Everyone else gets a locked notice instead
    // of live controls — "Assign to me" (or the owner's "Reassign…") is the
    // only way in.
    function isMine(t) {
      // Compared by id rather than name now that the API supplies one — two
      // agents sharing a display name would otherwise both "own" the ticket.
      return !!t.assignedAgentId && t.assignedAgentId === agent.id;
    }

    // Handing a ticket to a specific agent is allowed either as a genuine
    // reassignment (you currently own it) or as a direct claim-for-someone-
    // else on a ticket nobody has touched yet — so a teammate's ticket
    // doesn't have to be "assigned to me" first just to hand it over.
    function canReassign(t) {
      // Resolved means the ticket is sitting with the customer awaiting their
      // confirm-fix/reopen decision — swapping the owning agent mid-confirmation
      // doesn't make sense, so it's locked the same as Closed.
      if (t.status === 'Closed' || t.status === 'Resolved') return false;
      return isMine(t) || !t.assignedAgentId;
    }

    function renderStatusActions(t) {
      var wrap = document.getElementById('statusActions');
      wrap.innerHTML = '';

      if (!isMine(t)) {
        var lock = document.createElement('span');
        lock.className = 'history-status';
        lock.textContent = t.assignedAgent
          ? 'Assigned to ' + t.assignedAgent + ' — assign to yourself to act on it'
          : 'Unassigned — assign to yourself to act on it';
        wrap.appendChild(lock);
        return;
      }

      var moves = STATUS_TRANSITIONS[t.status] || [];
      moves.forEach(function (m) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn-ghost btn-inline';
        btn.textContent = m.label;
        // Escalating needs a target + reason first, and resolving needs a
        // summary first, so open the relevant panel instead of transitioning
        // straight away like every other status move does.
        if (m.to === 'Escalated') {
          btn.addEventListener('click', function () { openEscalatePanel(t); });
        } else if (m.to === 'Resolved') {
          btn.addEventListener('click', function () { openResolvePanel(t); });
        } else {
          btn.addEventListener('click', function () { changeStatus(t, m.to); });
        }
        wrap.appendChild(btn);
      });
      if (!moves.length) {
        var note = document.createElement('span');
        note.className = 'history-status';
        note.textContent = t.status === 'Resolved' ? 'Awaiting customer' : (t.status === 'Closed' ? 'Closed' : '');
        if (note.textContent) wrap.appendChild(note);
      }
    }

    // ---- Reassign / escalate ----
    // The reassign select is built from the shared agent directory (GET
    // /api/agents) at open time, so an agent added from the admin console shows
    // up here with no change to this file. It replaced AGENT_ROSTER, a
    // names-only copy with its own fetch — PATCH /assign takes an agent id, so
    // the select needs the full record. The directory has long since loaded by
    // the time a click opens the panel.
    // Drops an internal-only note into the ticket's real comment thread (see
    // postInternalNote above), so reassignments/escalations/resolutions leave
    // the same kind of trail agents already see for internal comments — now
    // visible to every agent/admin viewing this ticket, not just this browser.
    function addInternalNote(ticketId, text) {
      postInternalNote(ticketId, 'agent', agent.name, text);
    }

    var reassignPanel = document.getElementById('reassignPanel');
    var reassignSelect = document.getElementById('reassignSelect');
    var reassignNote = document.getElementById('reassignNote');
    var escalatePanel = document.getElementById('escalatePanel');
    var escalateSelect = document.getElementById('escalateSelect');
    var escalateReason = document.getElementById('escalateReason');
    var resolvePanel = document.getElementById('resolvePanel');
    var resolveSummaryField = document.getElementById('f-resolveSummary');
    var resolveSummaryInput = document.getElementById('resolveSummary');

    function closePanels() {
      reassignPanel.style.display = 'none';
      escalatePanel.style.display = 'none';
      if (resolvePanel) resolvePanel.style.display = 'none';
    }

    function openReassignPanel(t) {
      escalatePanel.style.display = 'none';
      if (resolvePanel) resolvePanel.style.display = 'none';
      reassignSelect.innerHTML = '';
      var unassignedOpt = document.createElement('option');
      unassignedOpt.value = '';
      unassignedOpt.textContent = 'Unassigned';
      if (!t.assignedAgent) unassignedOpt.selected = true;
      reassignSelect.appendChild(unassignedOpt);
      // Option values are agent ids — that's what PATCH /assign takes — with
      // the name shown as the label.
      loadAgents().filter(function (a) { return a.id !== agent.id; }).forEach(function (a) {
        var opt = document.createElement('option');
        opt.value = a.id; opt.textContent = a.name;
        if (a.id === t.assignedAgentId) opt.selected = true;
        reassignSelect.appendChild(opt);
      });
      reassignNote.value = '';
      clearPanelError(reassignPanel);
      var prompt = document.getElementById('reassignPrompt');
      if (prompt) prompt.textContent = t.assignedAgent ? 'Hand this ticket to another agent' : 'Assign this unclaimed ticket to an agent';
      reassignPanel.style.display = 'block';
    }

    function openEscalatePanel(t) {
      reassignPanel.style.display = 'none';
      if (resolvePanel) resolvePanel.style.display = 'none';
      clearPanelError(escalatePanel);
      escalateSelect.innerHTML = '';
      // An agent can't assign/reassign directly (PATCH /:id/assign stays
      // admin-only) — escalating just picks who it should go to next, and
      // the admin console's reassign dropdown pre-fills from this same
      // choice (suggested_agent_id) instead of showing a blank one.
      var otherAgents = loadAgents().filter(function (a) { return a.id !== agent.id; });
      otherAgents.forEach(function (a) {
        var opt = document.createElement('option');
        opt.value = a.id; opt.textContent = a.name;
        escalateSelect.appendChild(opt);
      });
      if (!otherAgents.length) {
        var noneOpt = document.createElement('option');
        noneOpt.value = '';
        noneOpt.textContent = 'No other agents available';
        escalateSelect.appendChild(noneOpt);
      }
      escalateReason.value = '';
      escalatePanel.style.display = 'block';
    }

    function openResolvePanel(t) {
      if (!resolvePanel) return;
      reassignPanel.style.display = 'none';
      escalatePanel.style.display = 'none';
      resolveSummaryInput.value = '';
      if (resolveSummaryField) resolveSummaryField.classList.remove('invalid');
      resolvePanel.style.display = 'block';
    }

    document.getElementById('reassignBtn').addEventListener('click', function () {
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
      if (!t) return;
      if (reassignPanel.style.display === 'block') { closePanels(); return; }
      openReassignPanel(t);
    });
    document.getElementById('reassignCancelBtn').addEventListener('click', closePanels);
    document.getElementById('reassignConfirmBtn').addEventListener('click', function () {
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
      if (!t || !canReassign(t)) { closePanels(); return; }
      var toId = reassignSelect.value; // '' means the Unassigned option was picked
      if (toId === (t.assignedAgentId || '')) { closePanels(); return; }

      // Captured before the request so the note reads correctly regardless of
      // what the server hands back.
      var wasUnassigned = !t.assignedAgentId;
      var from = t.assignedAgent || 'Unassigned';
      var toName = toId ? agentNameForId(toId) : null;
      var note = reassignNote.value.trim();
      var confirmBtn = document.getElementById('reassignConfirmBtn');

      clearPanelError(reassignPanel);
      confirmBtn.disabled = true;
      assignTicket(t, toId, function (updated) {
        confirmBtn.disabled = false;
        replaceTicketIn(tickets, updated);
        agentKnownSignature[updated.id] = ticketSignature(updated);
        var noteText = toName
          ? (wasUnassigned ? 'Assigned to ' + toName : 'Reassigned from ' + from + ' to ' + toName)
          : 'Unassigned (was ' + from + ')';
        addInternalNote(updated.id, noteText + (note ? ' — ' + note : '.'));
        closePanels();
        renderStats(); renderDetail(); renderList();
      }, function (err) {
        confirmBtn.disabled = false;
        if (showLatestAgentTicket(err)) return;
        showPanelError(reassignPanel, err.message || 'Unable to update the assignment.');
      });
    });

    document.getElementById('escalateCancelBtn').addEventListener('click', closePanels);
    document.getElementById('escalateConfirmBtn').addEventListener('click', function () {
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
      if (!t || !isMine(t)) { closePanels(); return; }
      var toId = escalateSelect.value;
      var reason = escalateReason.value.trim();
      clearPanelError(escalatePanel);
      if (!toId) { showPanelError(escalatePanel, 'Choose which agent to escalate this to.'); return; }
      if (!reason) { showPanelError(escalatePanel, 'Enter a reason for escalating.'); return; }
      if (!canTransition(t.status, 'Escalated')) { closePanels(); return; }

      var toName = agentNameForId(toId);
      var escalateConfirmBtnEl = document.getElementById('escalateConfirmBtn');
      escalateConfirmBtnEl.disabled = true;
      changeTicketStatus(t, { status: 'Escalated', escalated_to: toName, escalation_reason: reason, suggested_agent_id: toId }, function (updated) {
        escalateConfirmBtnEl.disabled = false;
        replaceTicketIn(tickets, updated);
        agentKnownSignature[updated.id] = ticketSignature(updated);
        addInternalNote(updated.id, 'Escalated to ' + toName + ' — ' + reason);
        closePanels();
        renderStats(); renderDetail(); renderList();
      }, function (err) {
        escalateConfirmBtnEl.disabled = false;
        if (showLatestAgentTicket(err)) return;
        showPanelError(escalatePanel, err.message || 'Unable to escalate this ticket.');
      });
    });

    // Resolving requires a summary — this is the only path that can set a
    // ticket to Resolved, so there's no way to skip leaving one.
    var resolveCancelBtn = document.getElementById('resolveCancelBtn');
    var resolveConfirmBtn = document.getElementById('resolveConfirmBtn');
    if (resolveCancelBtn) resolveCancelBtn.addEventListener('click', closePanels);
    if (resolveConfirmBtn) {
      resolveConfirmBtn.addEventListener('click', function () {
        var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
        if (!t || !isMine(t)) { closePanels(); return; }
        var summary = resolveSummaryInput.value.trim();
        if (!summary) {
          if (resolveSummaryField) resolveSummaryField.classList.add('invalid');
          resolveSummaryInput.focus();
          return;
        }
        if (resolveSummaryField) resolveSummaryField.classList.remove('invalid');
        if (!canTransition(t.status, 'Resolved')) { closePanels(); return; }

        clearPanelError(resolvePanel);
        resolveConfirmBtn.disabled = true;
        changeTicketStatus(t, { status: 'Resolved', resolution_summary: summary }, function (updated) {
          resolveConfirmBtn.disabled = false;
          replaceTicketIn(tickets, updated);
          agentKnownSignature[updated.id] = ticketSignature(updated);
          addInternalNote(updated.id, 'Marked resolved — ' + summary);
          closePanels();
          renderStats(); renderDetail(); renderList();
        }, function (err) {
          resolveConfirmBtn.disabled = false;
          if (showLatestAgentTicket(err)) return;
          showPanelError(resolvePanel, err.message || 'Unable to resolve this ticket.');
        });
      });
    }

    function renderStats() {
      var open = tickets.filter(function (t) { return isOpenStatus(t.status); }).length;
      var critical = tickets.filter(function (t) { return t.priority === 'Critical' && isOpenStatus(t.status); }).length;
      var unassigned = tickets.filter(function (t) { return !t.assignedAgent && isOpenStatus(t.status); }).length;
      var resolved = tickets.filter(function (t) { return t.status === 'Resolved' || t.status === 'Closed'; }).length;
      var mine = tickets.filter(isMine).length;

      var now = Date.now();
      var slaBreached = tickets.filter(function (t) { var a = slaAlert(t, now); return a && a.level === 'breached'; }).length;

      document.getElementById('statOpen').textContent = open;
      document.getElementById('statCritical').textContent = critical;
      document.getElementById('statSlaBreached').textContent = slaBreached;
      document.getElementById('statUnassigned').textContent = unassigned;
      document.getElementById('statResolved').textContent = resolved;
      document.getElementById('agentMineCount').textContent = mine;
    }

    function renderDetail() {
      var dash = document.getElementById('agentDash');
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];

      if (!t) {
        dash.style.display = 'none';
        return;
      }
      dash.style.display = 'block';
      closePanels();

      document.getElementById('dashId').textContent = t.id;
      document.getElementById('dashSubject').textContent = t.subject;
      document.getElementById('dashDescription').textContent = t.description ? t.description : 'No description provided.';
      document.getElementById('dashCategory').textContent = t.category;
      document.getElementById('dashPriority').textContent = t.priority;
      document.getElementById('dashTeam').textContent = t.team;
      renderSlaBox(document.getElementById('dashSla'), t);
      document.getElementById('dashFiles').textContent = t.files ? t.files + ' attached' : 'None';
      document.getElementById('dashEmail').textContent = t.email;
      document.getElementById('dashAgent').textContent = t.assignedAgent || 'Unassigned';

      var dashAttBlock = document.getElementById('dashAttachmentsBlock');
      if (dashAttBlock) {
        if (t.attachments && t.attachments.length) {
          renderAttachmentChips(document.getElementById('dashAttachmentsList'), t.attachments);
          dashAttBlock.style.display = '';
        } else {
          dashAttBlock.style.display = 'none';
        }
      }

      var serviceBox = document.getElementById('dashServiceBox');
      if (serviceBox) {
        if (t.service) {
          document.getElementById('dashService').textContent = t.service;
          serviceBox.style.display = '';
        } else {
          serviceBox.style.display = 'none';
        }
      }

      var badge = document.getElementById('dashStatusBadge');
      badge.textContent = t.status;
      badge.className = 'status-badge ' + statusClass(t.status);

      var assignBtn = document.getElementById('assignToMeBtn');
      assignBtn.disabled = isMine(t);
      assignBtn.textContent = isMine(t) ? 'Assigned to you' : 'Assign to me';
      var reassignBtn = document.getElementById('reassignBtn');
      reassignBtn.disabled = !canReassign(t);
      reassignBtn.textContent = t.assignedAgentId ? 'Reassign…' : 'Assign to…';
      renderStatusActions(t);
      document.getElementById('messageCustomerBtn').setAttribute('href', 'ticket-chat.html?ticket=' + encodeURIComponent(t.id) + '&role=agent');
      applyUnreadBadges();

      // Surface whether the customer has confirmed the fix or reopened the ticket.
      var resBanner = document.getElementById('dashResolutionBanner');
      var resText = document.getElementById('dashResolutionText');
      if (resBanner && resText) {
        if (t.status === 'Closed') {
          resBanner.style.display = 'flex';
          resText.innerHTML = 'Customer <strong>confirmed the fix</strong> — ticket closed.';
        } else if (t.status === 'Reopened') {
          resBanner.style.display = 'flex';
          resText.innerHTML = 'Customer <strong>reopened this ticket</strong> — take another look.';
        } else {
          resBanner.style.display = 'none';
        }
      }

      // Flag when the ticket is currently escalated and why.
      var escBanner = document.getElementById('dashEscalationBanner');
      var escText = document.getElementById('dashEscalationText');
      if (escBanner && escText) {
        if (t.status === 'Escalated' && t.escalation) {
          escBanner.style.display = 'flex';
          escText.innerHTML = 'Escalated to <strong>' + escapeHtml(t.escalation.to) + '</strong>' +
            (t.escalation.by ? ' by ' + escapeHtml(t.escalation.by) : '') + ': "' + escapeHtml(t.escalation.reason) + '"';
        } else {
          escBanner.style.display = 'none';
        }
      }

      // Show the resolution summary left when this ticket was marked resolved,
      // so it stays visible to any agent even after the customer reopens it.
      var resSummaryBanner = document.getElementById('dashResolutionSummaryBanner');
      var resSummaryText = document.getElementById('dashResolutionSummaryText');
      if (resSummaryBanner && resSummaryText) {
        if (t.resolutionSummary) {
          resSummaryBanner.style.display = 'flex';
          resSummaryText.textContent = t.resolutionSummary.by
            ? 'Resolution (' + t.resolutionSummary.by + '): ' + t.resolutionSummary.text
            : 'Resolution: ' + t.resolutionSummary.text;
        } else {
          resSummaryBanner.style.display = 'none';
        }
      }

      // Show the customer's CSAT rating, once they've submitted one.
      var csatBanner = document.getElementById('dashCsatBanner');
      if (csatBanner) {
        if (t.csat) {
          csatBanner.style.display = 'flex';
          var csatStars = document.getElementById('dashCsatStars');
          csatStars.innerHTML = '';
          for (var i = 1; i <= 5; i++) {
            var s = document.createElement('span');
            s.className = 'csat-star' + (i <= t.csat.score ? ' active' : '');
            s.textContent = '★';
            csatStars.appendChild(s);
          }
          var csatText = document.getElementById('dashCsatText');
          csatText.textContent = 'Customer rated this ' + t.csat.score + '/5' + (t.csat.comment ? ': "' + t.csat.comment + '"' : '.');
        } else {
          csatBanner.style.display = 'none';
        }
      }
    }

    function renderList() {
      var listEl = document.getElementById('queueList');
      var q = searchQuery.trim().toLowerCase();
      var filtered = tickets.filter(function (t) {
        if (currentFilter === 'Mine' && !isMine(t)) return false;
        if (currentFilter !== 'All' && currentFilter !== 'Mine' && t.priority !== currentFilter) return false;
        if (statusFilter && t.status !== statusFilter) return false;
        if (categoryFilter && t.category !== categoryFilter) return false;
        if (dateFilter) {
          var createdDate = t.createdAt ? t.createdAt.slice(0, 10) : '';
          if (createdDate !== dateFilter) return false;
        }
        if (q) {
          var haystack = (t.id + ' ' + t.subject + ' ' + (t.email || '')).toLowerCase();
          if (haystack.indexOf(q) === -1) return false;
        }
        return true;
      });

      listEl.innerHTML = '';

      if (!filtered.length) {
        listEl.innerHTML = '<p class="queue-no-results">No tickets match your search or filters.</p>';
        return;
      }

      var now = Date.now();
      filtered.forEach(function (t) {
        var row = document.createElement('div');
        var alertInfo = slaAlert(t, now);
        row.className = 'history-row ' + statusClass(t.status) + (alertInfo && alertInfo.level === 'breached' ? ' sla-breached-row' : '');
        row.dataset.ticketId = t.id;
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        row.setAttribute('aria-label', 'View details for ' + t.subject);
        if (t.id === selectedId) row.classList.add('active');
        row.innerHTML =
          '<div class="history-main">' +
            '<p class="history-id">' + escapeHtml(t.id) + '</p>' +
            '<p class="history-subject">' + escapeHtml(t.subject) + '</p>' +
          '</div>' +
          '<div class="history-meta">' +
            slaAlertChipHtml(t, now) +
            '<span class="history-chip">' + escapeHtml(t.category) + '</span>' +
            '<span class="history-chip">' + escapeHtml(t.priority) + '</span>' +
            '<span class="history-chip">' + (t.assignedAgent ? escapeHtml(t.assignedAgent) : '<span class="history-unassigned">Unassigned</span>') + '</span>' +
            '<span class="history-status">' + escapeHtml(t.status) + '</span>' +
          '</div>';
        row.addEventListener('click', function () { selectedId = t.id; renderDetail(); renderList(); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectedId = t.id; renderDetail(); renderList(); }
        });
        listEl.appendChild(row);
      });
      applyUnreadBadges();
    }

    document.getElementById('assignToMeBtn').addEventListener('click', function () {
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
      if (!t) return;
      var btn = document.getElementById('assignToMeBtn');
      btn.disabled = true; // re-enabled by renderDetail on success
      assignTicket(t, agent.id, function (updated) {
        replaceTicketIn(tickets, updated);
        // Keep the poll's signature in step so it doesn't re-render on top of
        // a change this tab just made.
        agentKnownSignature[updated.id] = ticketSignature(updated);
        renderStats(); renderDetail(); renderList();
      }, function (err) {
        btn.disabled = false;
        if (showLatestAgentTicket(err)) return;
        alert(err.message || 'Unable to assign this ticket.');
      });
    });

    document.querySelectorAll('.filter-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        document.querySelectorAll('.filter-chip').forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        currentFilter = chip.dataset.filter;
        renderList();
      });
    });

    // FR-14: search by ticket number/requester/subject, plus status/category/date filters
    var queueSearchInput = document.getElementById('queueSearchInput');
    var queueStatusFilter = document.getElementById('queueStatusFilter');
    var queueCategoryFilter = document.getElementById('queueCategoryFilter');
    var queueDateFilter = document.getElementById('queueDateFilter');
    var queueClearFilters = document.getElementById('queueClearFilters');

    if (queueSearchInput) {
      queueSearchInput.addEventListener('input', function () {
        searchQuery = queueSearchInput.value;
        renderList();
      });
    }
    if (queueStatusFilter) {
      queueStatusFilter.addEventListener('change', function () {
        statusFilter = queueStatusFilter.value;
        renderList();
      });
    }
    if (queueCategoryFilter) {
      queueCategoryFilter.addEventListener('change', function () {
        categoryFilter = queueCategoryFilter.value;
        renderList();
      });
    }
    if (queueDateFilter) {
      queueDateFilter.addEventListener('change', function () {
        dateFilter = queueDateFilter.value;
        renderList();
      });
    }
    if (queueClearFilters) {
      queueClearFilters.addEventListener('click', function () {
        searchQuery = ''; statusFilter = ''; categoryFilter = ''; dateFilter = '';
        if (queueSearchInput) queueSearchInput.value = '';
        if (queueStatusFilter) queueStatusFilter.value = '';
        if (queueCategoryFilter) queueCategoryFilter.value = '';
        if (queueDateFilter) queueDateFilter.value = '';
        renderList();
      });
    }

    // Renders whatever `tickets` currently holds. Called once the initial
    // fetch resolves. Pass `failed: true` when the fetch itself errored out
    // (after retries) — kept visually and semantically separate from a
    // genuinely empty queue, which used to render identically and silently.
    function bootstrapAgentQueue(failed) {
      var queueEmptyEl = document.getElementById('queueEmpty');
      var queueErrorEl = document.getElementById('queueLoadError');
      if (failed) {
        if (queueErrorEl) queueErrorEl.style.display = 'block';
        if (queueEmptyEl) queueEmptyEl.style.display = 'none';
        document.getElementById('agentDash').style.display = 'none';
        return;
      }
      if (queueErrorEl) queueErrorEl.style.display = 'none';
      if (!tickets.length) {
        if (queueEmptyEl) queueEmptyEl.style.display = 'block';
        document.getElementById('agentDash').style.display = 'none';
        return;
      }
      if (queueEmptyEl) queueEmptyEl.style.display = 'none';
      document.getElementById('agentDash').style.display = '';
      renderStats();
      renderDetail();
      renderList();
    }

    // ---- FR-4 (agent side): pick up ticket changes made elsewhere ----
    // An admin reassigning/escalating a ticket, or another agent acting on a
    // shared one, writes to the same `docketTickets` record from a different
    // tab/window. Without this, this queue would silently go stale until the
    // agent manually reloads. Mirrors the customer portal's live-update
    // handling below, but keyed on status+assignedAgent (a reassignment alone
    // doesn't change status) and re-renders in place rather than toasting.
    var agentKnownSignature = {};
    tickets.forEach(function (t) { agentKnownSignature[t.id] = ticketSignature(t); });

    function applyRemoteAgentUpdate(updated) {
      if (!updated) return;

      // Only re-render on an actual change — the poll fires every 4s and a
      // careless unconditional re-render would blow away whatever an agent
      // is mid-typing in an open reassign/escalate/resolve panel.
      var changed = updated.length !== tickets.length;
      updated.forEach(function (t) {
        var sig = ticketSignature(t);
        if (agentKnownSignature[t.id] !== sig) changed = true;
        agentKnownSignature[t.id] = sig;
      });
      if (!changed) return;

      tickets = updated;
      if (selectedId && !tickets.some(function (t) { return t.id === selectedId; })) {
        selectedId = tickets.length ? tickets[0].id : null;
      }
      if (!tickets.length) {
        document.getElementById('queueEmpty').style.display = 'block';
        document.getElementById('agentDash').style.display = 'none';
      } else {
        document.getElementById('queueEmpty').style.display = 'none';
        document.getElementById('agentDash').style.display = '';
        renderStats(); renderDetail(); renderList();
      }
    }

    // Initial load. The agent and user directories are warmed first because
    // normalizeTicket() reads both to resolve assignedAgent and the requester
    // email the queue search matches against. Wrapped in a named function so
    // the Retry button (shown on the failed-load state) can call it again.
    function loadAgentQueue() {
      withDirectories(function () {
        fetchTicketsWithRetry(null, function (rows) {
          tickets = rows;
          selectedId = tickets.length ? tickets[0].id : null;
          tickets.forEach(function (t) {
            agentKnownSignature[t.id] = ticketSignature(t);
          });
          bootstrapAgentQueue();
        }, function (err) {
          if (err && err.status === 401 && handleAuthExpired()) return;
          bootstrapAgentQueue(true);
        });
      });
    }
    loadAgentQueue();
    var queueRetryBtn = document.getElementById('queueRetryBtn');
    if (queueRetryBtn) queueRetryBtn.addEventListener('click', loadAgentQueue);

    // The `storage` listener that used to drive this is gone along with the
    // localStorage ticket store; the poll is now the only path by which this
    // queue notices a change made elsewhere. Still a no-op until a status or
    // assignment actually moves, so an open reassign/escalate/resolve panel
    // doesn't get blown away mid-edit.
    setInterval(function () {
      fetchTickets(null, applyRemoteAgentUpdate);
    }, 4000);

    // SLA warnings depend on the clock as well as the data, so refresh them
    // once a minute even when the poll above sees no change. Deliberately
    // not renderDetail(), which would close any panel mid-edit — only the
    // SLA box in the detail view is updated.
    setInterval(function () {
      if (!tickets.length) return;
      renderStats(); renderList();
      var t = tickets.filter(function (x) { return x.id === selectedId; })[0];
      if (t) renderSlaBox(document.getElementById('dashSla'), t);
    }, 60000);
  }

  // ---- Ticket chat (ticket-chat.html): shared thread between agent and customer ----
  var chatThread = document.getElementById('chatThread');
  if (chatThread) {
    var chatParams = new URLSearchParams(window.location.search);
    var chatTicketId = chatParams.get('ticket');
    var chatRoleParam = chatParams.get('role');
    var chatRole = chatRoleParam === 'agent' ? 'agent' : (chatRoleParam === 'admin' ? 'admin' : 'customer');

    var chatActor = null;
    if (chatRole === 'agent') {
      chatActor = readSession('docketAgent');
      if (!chatActor) { window.location.href = 'agent-login.html'; return; }
    } else if (chatRole === 'admin') {
      chatActor = readSession('docketAdmin');
      if (!chatActor) { window.location.href = 'admin-login.html'; return; }
    } else {
      try { chatActor = JSON.parse(localStorage.getItem('docketUser')); } catch (e) { chatActor = null; }
      if (!chatActor) { window.location.href = 'landing.html'; return; }
    }
    var chatActorName = (chatRole === 'agent' || chatRole === 'admin') ? chatActor.name : chatActor.name.split(' ')[0];

    document.getElementById('chatRoleBadge').innerHTML = '<span class="dot"></span>' +
      (chatRole === 'agent' ? 'Agent Console' : chatRole === 'admin' ? 'Admin Console' : 'Customer Portal');
    document.getElementById('chatBackBtn').addEventListener('click', function () {
      window.location.href = chatRole === 'agent' ? 'agent-dashboard.html' : chatRole === 'admin' ? 'admin-dashboard.html' : 'portal.html';
    });

    // The chat header needs the ticket's subject and priority, fetched from
    // the API below. The messages themselves are now fetched the same way
    // (GET /api/tickets/:id/comments) instead of a `docketChat:<id>`
    // localStorage thread, so every viewer of this ticket sees the same
    // conversation regardless of which browser wrote each message.
    var chatTicket = null;
    var chatMessages = [];

    var chatInput = document.getElementById('chatInput');
    var chatSendBtn = document.getElementById('chatSendBtn');
    var chatVisibility = 'public';
    var visToggle = document.getElementById('chatVisibilityToggle');

    var chatEscapeHtml = function (str) {
      return str.replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
    };

    // Pending attachments for the message currently being composed
    var chatFiles = [];
    var chatAttachBtn = document.getElementById('chatAttachBtn');
    var chatAttachInput = document.getElementById('chatAttachInput');
    var chatFileListEl = document.getElementById('chatFileList');

    function renderChatFiles() {
      if (!chatFileListEl) return;
      chatFileListEl.innerHTML = '';
      chatFiles.forEach(function (file, i) {
        var chip = document.createElement('span');
        chip.className = 'file-chip';
        chip.innerHTML = '<span>' + chatEscapeHtml(file.name) + '</span>';
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Remove ' + file.name);
        btn.textContent = '✕';
        btn.addEventListener('click', function () { chatFiles.splice(i, 1); renderChatFiles(); });
        chip.appendChild(btn);
        chatFileListEl.appendChild(chip);
      });
    }

    if (chatAttachBtn && chatAttachInput) {
      chatAttachBtn.addEventListener('click', function () { chatAttachInput.click(); });
      chatAttachInput.addEventListener('change', function () {
        Array.prototype.forEach.call(chatAttachInput.files, function (f) { chatFiles.push(f); });
        chatAttachInput.value = '';
        renderChatFiles();
      });
    }

    // The ticket's "files attached" count is computed server-side from
    // ticket_attachments (see attachmentCount() in routes/tickets.js), which
    // already only counts a chat attachment once it's on a *public* comment —
    // so there's nothing to do here on send; the portal/agent dashboard picks
    // it up next time they fetch the ticket.

    if ((chatRole === 'agent' || chatRole === 'admin') && visToggle) {
      visToggle.style.display = 'flex';
      visToggle.querySelectorAll('.vis-chip').forEach(function (chip) {
        chip.addEventListener('click', function () {
          visToggle.querySelectorAll('.vis-chip').forEach(function (c) { c.classList.remove('active'); });
          chip.classList.add('active');
          chatVisibility = chip.dataset.visibility;
          chatSendBtn.textContent = chatVisibility === 'internal' ? 'Add note' : 'Send';
          chatInput.placeholder = chatVisibility === 'internal'
            ? 'Add an internal note — not visible to the customer'
            : 'Type a message… share the steps to fix this issue';
        });
      });
    }

    // Renders whatever `chatMessages` currently holds (kept in memory,
    // refreshed from the API by the initial load and the poll below).
    function renderChatMessages() {
      var msgs = chatMessages;
      // Customers only ever see public comments; internal notes are agent/team-only.
      if (chatRole === 'customer') {
        msgs = msgs.filter(function (m) { return m.visibility !== 'internal'; });
      }
      chatThread.innerHTML = '';
      if (!msgs.length) {
        chatThread.innerHTML = '<p class="chat-empty">No messages yet — say hello or share the steps to fix this.</p>';
        return;
      }
      msgs.forEach(function (m) {
        var isInternal = m.visibility === 'internal';
        var mine = m.from === chatRole;
        var bubble = document.createElement('div');
        bubble.className = 'chat-bubble ' + (isInternal ? 'internal' : (mine ? 'out' : 'in'));
        var label = isInternal
          ? (mine ? 'You · Internal note' : chatEscapeHtml(m.name) + ' · Internal note')
          : (mine ? 'You' : chatEscapeHtml(m.name));
        var filesHtml = '';
        if (m.files && m.files.length) {
          // GET /api/attachments/:id requires an Authorization header, which
          // a plain href can't send — chips carry the id as a data attribute
          // instead, and get a click handler wired up below that fetches the
          // file with the current actor's token (see downloadAttachment()).
          filesHtml = '<div class="chat-attachments">' + m.files.map(function (f) {
            var isObj = f && typeof f === 'object';
            var name = isObj ? f.filename : f;
            var id = isObj ? f.id : null;
            return id != null
              ? '<a class="chat-attachment-chip" href="#" data-attachment-id="' + escapeHtml(id) + '">📎 ' + chatEscapeHtml(name) + '</a>'
              : '<span class="chat-attachment-chip">📎 ' + chatEscapeHtml(name) + '</span>';
          }).join('') + '</div>';
        }
        bubble.innerHTML =
          '<span class="chat-name">' + label + '</span>' +
          (m.text ? chatEscapeHtml(m.text) : '') +
          filesHtml +
          '<span class="chat-time">' + escapeHtml(m.time) + '</span>';
        var downloadableFiles = m.files.filter(function (f) { return f && typeof f === 'object' && f.id != null; });
        bubble.querySelectorAll('.chat-attachment-chip[data-attachment-id]').forEach(function (chip, i) {
          var f = downloadableFiles[i];
          chip.addEventListener('click', function (e) {
            e.preventDefault();
            previewAttachment(chip.getAttribute('data-attachment-id'), f && f.filename);
          });
        });
        chatThread.appendChild(bubble);
      });
      chatThread.scrollTop = chatThread.scrollHeight;
    }

    function sendChatMessage() {
      var text = chatInput.value.trim();
      if (!text && !chatFiles.length) return;
      var visibility = ((chatRole === 'agent' || chatRole === 'admin') && chatVisibility === 'internal') ? 'internal' : 'public';
      var filesToSend = chatFiles.slice();

      chatSendBtn.disabled = true;
      // Same read-before-send pattern as ticket creation: the files are
      // read into base64 client-side, then posted alongside the message
      // text in one comment.
      Promise.all(filesToSend.map(readFileAsAttachment))
        .then(function (attachments) {
          postComment(chatTicket.id, chatRole, chatActorName, text, visibility, attachments, function (comment) {
            chatSendBtn.disabled = false;
            chatMessages.push(comment);
            chatInput.value = '';
            chatFiles = [];
            renderChatFiles();
            renderChatMessages();
          }, function (err) {
            chatSendBtn.disabled = false;
            alert(err.message || 'Unable to send that message. Please try again.');
          });
        })
        .catch(function (err) {
          chatSendBtn.disabled = false;
          alert(err.message || 'Unable to attach one of those files. Please try again.');
        });
    }

    function initChat() {
      if (!chatTicket) {
        document.getElementById('chatTicketId').textContent = 'Ticket not found';
        document.getElementById('chatTicketSubject').textContent = '';
        document.getElementById('chatTicketPriority').style.display = 'none';
        chatInput.disabled = true;
        chatSendBtn.disabled = true;
        if (chatAttachBtn) chatAttachBtn.disabled = true;
        chatThread.innerHTML = '<p class="chat-empty">This ticket could not be found.</p>';
        return;
      }
      document.getElementById('chatTicketId').textContent = chatTicket.id;
      document.getElementById('chatTicketSubject').textContent = chatTicket.subject;
      document.getElementById('chatTicketPriority').textContent = chatTicket.priority;

      chatSendBtn.addEventListener('click', sendChatMessage);
      chatInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
      });

      renderChatMessages();
      markChatRead();
    }

    // GET /api/tickets/:id — a 404 (or a bad ?ticket= param) falls through to
    // initChat's existing "not found" branch, which disables the composer.
    // Comments are only fetched once the ticket itself is confirmed to exist.
    fetch(API_BASE + '/api/tickets/' + encodeURIComponent(chatTicketId), { headers: authHeaders() })
      .then(function (response) {
        if (response.status === 401 && handleAuthExpired()) return null;
        return response.ok ? response.json() : null;
      })
      .then(function (row) {
        if (!row) { initChat(); return; }
        chatTicket = normalizeTicket(row);
        fetchComments(chatTicket.id, function (comments) {
          chatMessages = comments;
          initChat();
        }, function () {
          chatMessages = [];
          initChat();
        });
      })
      .catch(function (err) {
        console.error('Chat ticket load error:', err);
        initChat();
      });

    // Read receipts for the unread badges / email reminders: whatever is on
    // screen counts as read, but only while the tab is actually visible — a
    // chat left open in a background tab shouldn't swallow new messages.
    var chatLastMarkedId = 0;
    function markChatRead() {
      if (!chatTicket || document.hidden) return;
      var maxId = chatMessages.reduce(function (max, m) { return m.id > max ? m.id : max; }, 0);
      if (maxId <= chatLastMarkedId) return;
      chatLastMarkedId = maxId;
      fetch(API_BASE + '/api/tickets/' + encodeURIComponent(chatTicket.id) + '/comments/read', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ up_to_id: maxId })
      })
        .then(function (response) { if (!response.ok) throw new Error('mark read failed (' + response.status + ')'); })
        .catch(function (err) {
          chatLastMarkedId = 0; // try again on the next poll
          console.error('Chat read receipt:', err);
        });
    }
    document.addEventListener('visibilitychange', markChatRead);

    // Live updates: the other side of this conversation (customer vs. agent/
    // admin) is very likely on a different device entirely, so — same
    // pattern as the ticket queues — poll for new comments rather than
    // relying on a same-browser signal that will never fire here.
    setInterval(function () {
      if (!chatTicket) return;
      fetchComments(chatTicket.id, function (comments) {
        if (comments.length !== chatMessages.length) {
          chatMessages = comments;
          renderChatMessages();
        }
        markChatRead();
      });
    }, 4000);
  }

  // ---- Portal topbar actions ----
  var backBtn = document.getElementById('backBtn');
  if (backBtn) {
    backBtn.addEventListener('click', function () {
      if (document.referrer && document.referrer.indexOf(window.location.host) !== -1) {
        window.history.back();
      } else {
        window.location.href = 'ticket.html';
      }
    });
  }

  var logoutBtn = document.getElementById('logoutBtn');
  if (logoutBtn) {
    var customerSignOut = function () {
      localStorage.removeItem('docketUser');
      window.location.href = 'login.html';
    };
    logoutBtn.addEventListener('click', customerSignOut);
    wireSignOutEverywhere('signOutAllBtn', customerSignOut);
  }

  // ---- Admin console (admin-dashboard.html): sitewide queue overview, assign/reassign
  // any ticket regardless of who currently holds it, and manage the agent directory ----
  var adminConsole = document.getElementById('adminConsole');
  if (adminConsole) {
    var adminUser = readSession('docketAdmin');
    if (!adminUser) {
      window.location.href = 'admin-login.html';
      return;
    }

    var adminInitials = adminUser.name.trim().split(/\s+/).map(function (p) { return p[0]; }).slice(0, 2).join('').toUpperCase() || '?';
    document.getElementById('adminInitials').textContent = adminInitials;
    document.getElementById('adminName').textContent = adminUser.name;
    document.getElementById('adminId').textContent = adminUser.id;
    document.getElementById('adminEmailDisplay').textContent = adminUser.email;
    document.getElementById('adminChipInitials').textContent = adminInitials;
    document.getElementById('adminChipName').textContent = adminUser.name.split(' ')[0];

    function adminSignOut() {
      clearSession('docketAdmin');
      window.location.href = 'admin-login.html';
    }
    document.getElementById('adminLogoutBtn').addEventListener('click', adminSignOut);
    wireSignOutEverywhere('adminSignOutAllBtn', adminSignOut);

    // Load the agent directory once up front (see refreshAgentDirectory above);
    // everything below reads the synchronous loadAgents() cache and just gets
    // re-rendered here once the real data is in.
    refreshAgentDirectory(function () {
      renderAdminStats();
      populateAssigneeFilter();
      var agentsPanel = document.getElementById('adminAgentsPanel');
      if (agentsPanel && agentsPanel.style.display !== 'none') renderAgentDirectory();
    });

    // Tickets — fetched from the API at the bottom of this block, the same
    // GET /api/tickets the agent queue reads, so the two consoles are looking
    // at one source of truth again rather than a shared localStorage array.
    var adminTickets = [];

    // (persistAdminTickets is gone — the admin console's only write was
    // assignment, which now goes through PATCH /api/tickets/:id/assign.)

    function adminStatusClass(status) {
      if (status === 'Resolved') return 'status-resolved';
      if (status === 'Closed') return 'status-closed';
      if (status === 'Reopened') return 'status-reopened';
      if (status === 'In Progress') return 'status-progress';
      if (status === 'Waiting') return 'status-waiting';
      if (status === 'Escalated') return 'status-escalated';
      return '';
    }
    function adminIsOpen(status) { return status !== 'Resolved' && status !== 'Closed'; }

    var adminSelectedId = adminTickets.length ? adminTickets[0].id : null;
    var adminSearchQuery = '', adminStatusFilter = '', adminCategoryFilter = '', adminAssigneeFilter = '';

    function renderAdminStats() {
      document.getElementById('adminStatOpen').textContent = adminTickets.filter(function (t) { return adminIsOpen(t.status); }).length;
      document.getElementById('adminStatCritical').textContent = adminTickets.filter(function (t) { return t.priority === 'Critical' && adminIsOpen(t.status); }).length;
      var now = Date.now();
      document.getElementById('adminStatSlaBreached').textContent = adminTickets.filter(function (t) { var a = slaAlert(t, now); return a && a.level === 'breached'; }).length;
      document.getElementById('adminStatUnassigned').textContent = adminTickets.filter(function (t) { return !t.assignedAgent && adminIsOpen(t.status); }).length;
      document.getElementById('adminStatResolved').textContent = adminTickets.filter(function (t) { return t.status === 'Resolved' || t.status === 'Closed'; }).length;
      document.getElementById('adminSidebarTicketCount').textContent = adminTickets.length;
      document.getElementById('adminSidebarAgentCount').textContent = loadAgents().length;
    }

    // Same internal-note trail agents leave for reassign/escalate, so an admin's
    // assignment shows up in the ticket's real comment thread too. Posted as
    // author_type 'admin' with "(Admin)" folded into the name so agents
    // viewing the same thread can tell it apart from a regular agent note.
    function addAdminNote(ticketId, text) {
      postInternalNote(ticketId, 'admin', adminUser.name + ' (Admin)', text);
    }

    var adminAssignPanel = document.getElementById('adminAssignPanel');
    var adminAssignSelect = document.getElementById('adminAssignSelect');
    var adminAssignNote = document.getElementById('adminAssignNote');

    function openAdminAssignPanel(t) {
      adminAssignSelect.innerHTML = '';
      // An escalating agent's suggested_agent_id (see openEscalatePanel) only
      // pre-selects here when the ticket has no current assignee — an actual
      // assignment always takes priority over a stale suggestion.
      var preselectId = t.assignedAgentId || t.suggestedAgentId;
      var unassignedOpt = document.createElement('option');
      unassignedOpt.value = '';
      unassignedOpt.textContent = 'Unassigned';
      if (!preselectId) unassignedOpt.selected = true;
      adminAssignSelect.appendChild(unassignedOpt);
      // Option values are agent ids — what PATCH /assign takes — labelled by name.
      loadAgents().forEach(function (a) {
        var opt = document.createElement('option');
        opt.value = a.id; opt.textContent = a.name + (!t.assignedAgentId && a.id === t.suggestedAgentId ? ' (suggested)' : '');
        if (a.id === preselectId) opt.selected = true;
        adminAssignSelect.appendChild(opt);
      });
      adminAssignNote.value = '';
      clearPanelError(adminAssignPanel);
      adminAssignPanel.style.display = 'block';
    }
    function closeAdminAssignPanel() { adminAssignPanel.style.display = 'none'; }

    document.getElementById('adminAssignBtn').addEventListener('click', function () {
      var t = adminTickets.filter(function (x) { return x.id === adminSelectedId; })[0];
      if (!t) return;
      if (adminAssignPanel.style.display === 'block') { closeAdminAssignPanel(); return; }
      openAdminAssignPanel(t);
    });
    document.getElementById('adminAssignCancelBtn').addEventListener('click', closeAdminAssignPanel);
    document.getElementById('adminAssignConfirmBtn').addEventListener('click', function () {
      var t = adminTickets.filter(function (x) { return x.id === adminSelectedId; })[0];
      if (!t) return;
      var toId = adminAssignSelect.value; // '' means the Unassigned option was picked
      if (toId === (t.assignedAgentId || '')) { closeAdminAssignPanel(); return; }

      var from = t.assignedAgent || 'Unassigned';
      var toName = toId ? agentNameForId(toId) : null;
      var note = adminAssignNote.value.trim();
      var confirmBtn = document.getElementById('adminAssignConfirmBtn');

      clearPanelError(adminAssignPanel);
      confirmBtn.disabled = true;
      assignTicket(t, toId, function (updated) {
        confirmBtn.disabled = false;
        replaceTicketIn(adminTickets, updated);
        adminKnownSignature[updated.id] = ticketSignature(updated);
        var noteText = toName
          ? (from === 'Unassigned' ? 'Assigned to ' + toName : 'Reassigned from ' + from + ' to ' + toName)
          : 'Unassigned (was ' + from + ')';
        addAdminNote(updated.id, noteText + ' by an admin' + (note ? ' — ' + note : '.'));
        closeAdminAssignPanel();
        renderAdminStats(); renderAdminDetail(); renderAdminList();
      }, function (err) {
        confirmBtn.disabled = false;
        if (err && err.latest) {
          // Refused as stale (409): show the ticket as it is now.
          replaceTicketIn(adminTickets, err.latest);
          adminKnownSignature[err.latest.id] = ticketSignature(err.latest);
          closeAdminAssignPanel();
          renderAdminStats(); renderAdminDetail(); renderAdminList();
          alert(err.message);
          return;
        }
        showPanelError(adminAssignPanel, err.message || 'Unable to update the assignment.');
      });
    });

    // Shared by the ticket and agent delete buttons — both are admin-only
    // DELETE routes that only need a success/failure back.
    function adminDelete(path) {
      return fetch(API_BASE + path, { method: 'DELETE', headers: authHeaders() })
        .then(function (response) {
          if (response.status === 401 && handleAuthExpired()) return new Promise(function () {});
          if (response.ok) return null;
          return response.json().catch(function () { return {}; }).then(function (data) {
            throw new Error(data.error || 'Request failed.');
          });
        });
    }

    document.getElementById('adminDeleteTicketBtn').addEventListener('click', function () {
      var t = adminTickets.filter(function (x) { return x.id === adminSelectedId; })[0];
      if (!t) return;
      if (!confirm('Permanently delete ' + t.id + ' ("' + t.subject + '")? Its conversation and attachments will be deleted too. This cannot be undone.')) return;

      var btn = this;
      btn.disabled = true;
      adminDelete('/api/tickets/' + encodeURIComponent(t.id))
        .then(function () {
          delete adminKnownSignature[t.id];
          applyRemoteAdminUpdate(adminTickets.filter(function (x) { return x.id !== t.id; }));
        })
        .catch(function (err) { alert(err.message || 'Unable to delete this ticket.'); })
        .finally(function () { btn.disabled = false; });
    });

    function renderAdminDetail() {
      var dash = document.getElementById('adminDash');
      var t = adminTickets.filter(function (x) { return x.id === adminSelectedId; })[0];
      if (!t) { dash.style.display = 'none'; return; }
      dash.style.display = 'block';
      closeAdminAssignPanel();

      document.getElementById('adminDashId').textContent = t.id;
      document.getElementById('adminDashSubject').textContent = t.subject;
      document.getElementById('adminDashDescription').textContent = t.description ? t.description : 'No description provided.';
      document.getElementById('adminDashCategory').textContent = t.category;
      document.getElementById('adminDashPriority').textContent = t.priority;
      document.getElementById('adminDashTeam').textContent = t.team;
      renderSlaBox(document.getElementById('adminDashSla'), t);
      document.getElementById('adminDashFiles').textContent = t.files ? t.files + ' attached' : 'None';
      document.getElementById('adminDashEmail').textContent = t.email;
      document.getElementById('adminDashAgent').textContent = t.assignedAgent || 'Unassigned';

      var adminAttBlock = document.getElementById('adminDashAttachmentsBlock');
      if (adminAttBlock) {
        if (t.attachments && t.attachments.length) {
          renderAttachmentChips(document.getElementById('adminDashAttachmentsList'), t.attachments);
          adminAttBlock.style.display = '';
        } else {
          adminAttBlock.style.display = 'none';
        }
      }

      var badge = document.getElementById('adminDashStatusBadge');
      badge.textContent = t.status;
      badge.className = 'status-badge ' + adminStatusClass(t.status);

      // Mirrors the server's own PATCH /:id/assign guard (and the agent
      // dashboard's canReassign) — Resolved is awaiting the customer's
      // confirm-fix/reopen call, and Closed is done, so swapping the agent
      // on either doesn't make sense.
      var assignLocked = t.status === 'Closed' || t.status === 'Resolved';
      var adminAssignBtnEl = document.getElementById('adminAssignBtn');
      adminAssignBtnEl.disabled = assignLocked;
      adminAssignBtnEl.title = assignLocked ? 'Cannot reassign a ' + t.status.toLowerCase() + ' ticket.' : '';

      var serviceBox = document.getElementById('adminDashServiceBox');
      if (t.service) {
        document.getElementById('adminDashService').textContent = t.service;
        serviceBox.style.display = '';
      } else {
        serviceBox.style.display = 'none';
      }

      var escBanner = document.getElementById('adminDashEscalationBanner');
      var escText = document.getElementById('adminDashEscalationText');
      if (t.status === 'Escalated' && t.escalation) {
        escBanner.style.display = 'flex';
        escText.innerHTML = 'Escalated to <strong>' + escapeHtml(t.escalation.to) + '</strong>' +
          (t.escalation.by ? ' by ' + escapeHtml(t.escalation.by) : '') + ': "' + escapeHtml(t.escalation.reason) + '"';
      } else {
        escBanner.style.display = 'none';
      }

      document.getElementById('adminOpenChatBtn').setAttribute('href', 'ticket-chat.html?ticket=' + encodeURIComponent(t.id) + '&role=admin');
    }

    function renderAdminList() {
      var listEl = document.getElementById('adminQueueList');
      var q = adminSearchQuery.trim().toLowerCase();
      var filtered = adminTickets.filter(function (t) {
        if (adminStatusFilter && t.status !== adminStatusFilter) return false;
        if (adminCategoryFilter && t.category !== adminCategoryFilter) return false;
        if (adminAssigneeFilter === 'Unassigned' && t.assignedAgent) return false;
        if (adminAssigneeFilter && adminAssigneeFilter !== 'Unassigned' && t.assignedAgent !== adminAssigneeFilter) return false;
        if (q) {
          var haystack = (t.id + ' ' + t.subject + ' ' + (t.email || '')).toLowerCase();
          if (haystack.indexOf(q) === -1) return false;
        }
        return true;
      });

      listEl.innerHTML = '';
      if (!filtered.length) {
        listEl.innerHTML = '<p class="queue-no-results">No tickets match your search or filters.</p>';
        return;
      }

      var now = Date.now();
      filtered.forEach(function (t) {
        var row = document.createElement('div');
        var alertInfo = slaAlert(t, now);
        row.className = 'history-row ' + adminStatusClass(t.status) + (alertInfo && alertInfo.level === 'breached' ? ' sla-breached-row' : '');
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        row.setAttribute('aria-label', 'View details for ' + t.subject);
        if (t.id === adminSelectedId) row.classList.add('active');
        row.innerHTML =
          '<div class="history-main">' +
            '<p class="history-id">' + escapeHtml(t.id) + '</p>' +
            '<p class="history-subject">' + escapeHtml(t.subject) + '</p>' +
          '</div>' +
          '<div class="history-meta">' +
            slaAlertChipHtml(t, now) +
            '<span class="history-chip">' + escapeHtml(t.category) + '</span>' +
            '<span class="history-chip">' + escapeHtml(t.priority) + '</span>' +
            '<span class="history-chip">' + (t.assignedAgent ? escapeHtml(t.assignedAgent) : '<span class="history-unassigned">Unassigned</span>') + '</span>' +
            '<span class="history-status">' + escapeHtml(t.status) + '</span>' +
          '</div>';
        row.addEventListener('click', function () { adminSelectedId = t.id; renderAdminDetail(); renderAdminList(); });
        row.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); adminSelectedId = t.id; renderAdminDetail(); renderAdminList(); }
        });
        listEl.appendChild(row);
      });
    }

    var aqAssignee = document.getElementById('adminQueueAssigneeFilter');
    // Re-runnable (not just a one-time forEach) so it can be called again once
    // refreshAgentDirectory's fetch resolves, without duplicating options.
    function populateAssigneeFilter() {
      if (!aqAssignee) return;
      Array.prototype.slice.call(aqAssignee.querySelectorAll('option[data-agent-option]')).forEach(function (opt) { opt.remove(); });
      loadAgents().forEach(function (a) {
        var opt = document.createElement('option');
        opt.value = a.name; opt.textContent = a.name;
        opt.setAttribute('data-agent-option', '1');
        aqAssignee.appendChild(opt);
      });
    }
    populateAssigneeFilter();
    var aqSearch = document.getElementById('adminQueueSearchInput');
    var aqStatus = document.getElementById('adminQueueStatusFilter');
    var aqCategory = document.getElementById('adminQueueCategoryFilter');
    var aqClear = document.getElementById('adminQueueClearFilters');
    if (aqSearch) aqSearch.addEventListener('input', function () { adminSearchQuery = aqSearch.value; renderAdminList(); });
    if (aqStatus) aqStatus.addEventListener('change', function () { adminStatusFilter = aqStatus.value; renderAdminList(); });
    if (aqCategory) aqCategory.addEventListener('change', function () { adminCategoryFilter = aqCategory.value; renderAdminList(); });
    if (aqAssignee) aqAssignee.addEventListener('change', function () { adminAssigneeFilter = aqAssignee.value; renderAdminList(); });
    if (aqClear) {
      aqClear.addEventListener('click', function () {
        adminSearchQuery = ''; adminStatusFilter = ''; adminCategoryFilter = ''; adminAssigneeFilter = '';
        if (aqSearch) aqSearch.value = '';
        if (aqStatus) aqStatus.value = '';
        if (aqCategory) aqCategory.value = '';
        if (aqAssignee) aqAssignee.value = '';
        renderAdminList();
      });
    }

    // Renders whatever `adminTickets` currently holds. Called once the initial
    // fetch resolves. Pass `failed: true` when the fetch itself errored out
    // (after retries) — see the matching agent-queue change above for why
    // this is kept separate from a genuinely empty queue.
    function bootstrapAdminConsole(failed) {
      var adminQueueEmptyEl = document.getElementById('adminQueueEmpty');
      var adminQueueErrorEl = document.getElementById('adminQueueLoadError');
      if (failed) {
        if (adminQueueErrorEl) adminQueueErrorEl.style.display = 'block';
        if (adminQueueEmptyEl) adminQueueEmptyEl.style.display = 'none';
        document.getElementById('adminDash').style.display = 'none';
        return;
      }
      if (adminQueueErrorEl) adminQueueErrorEl.style.display = 'none';
      if (!adminTickets.length) {
        if (adminQueueEmptyEl) adminQueueEmptyEl.style.display = 'block';
        document.getElementById('adminDash').style.display = 'none';
        return;
      }
      if (adminQueueEmptyEl) adminQueueEmptyEl.style.display = 'none';
      document.getElementById('adminDash').style.display = '';
      renderAdminStats(); renderAdminDetail(); renderAdminList();
    }

    // ---- FR-4 (admin side): pick up ticket changes made elsewhere ----
    // Same gap as the agent queue — an agent moving a ticket's status (or
    // another admin reassigning one) writes to `docketTickets` from a
    // different tab/window, and this console would otherwise sit stale
    // until reloaded. See the matching block in the agent-queue section
    // above for the fuller rationale; kept as a separate copy here since
    // it drives a different ticket array and set of render functions.
    var adminKnownSignature = {};
    adminTickets.forEach(function (t) { adminKnownSignature[t.id] = ticketSignature(t); });

    function applyRemoteAdminUpdate(updated) {
      if (!updated) return;

      var changed = updated.length !== adminTickets.length;
      updated.forEach(function (t) {
        var sig = ticketSignature(t);
        if (adminKnownSignature[t.id] !== sig) changed = true;
        adminKnownSignature[t.id] = sig;
      });
      if (!changed) return;

      adminTickets = updated;
      if (adminSelectedId && !adminTickets.some(function (t) { return t.id === adminSelectedId; })) {
        adminSelectedId = adminTickets.length ? adminTickets[0].id : null;
      }
      if (!adminTickets.length) {
        document.getElementById('adminQueueEmpty').style.display = 'block';
        document.getElementById('adminDash').style.display = 'none';
      } else {
        document.getElementById('adminQueueEmpty').style.display = 'none';
        document.getElementById('adminDash').style.display = '';
        renderAdminStats(); renderAdminDetail(); renderAdminList();
      }
    }

    // Initial load — directories first, same reason as the agent queue: the
    // assignee filter and the queue search both match on names and requester
    // emails that normalizeTicket() resolves from those caches. Wrapped in a
    // named function so the Retry button (shown on the failed-load state)
    // can call it again.
    function loadAdminConsole() {
      withDirectories(function () {
        fetchTicketsWithRetry(null, function (rows) {
          adminTickets = rows;
          adminSelectedId = adminTickets.length ? adminTickets[0].id : null;
          adminTickets.forEach(function (t) {
            adminKnownSignature[t.id] = ticketSignature(t);
          });
          populateAssigneeFilter();
          bootstrapAdminConsole();
        }, function (err) {
          if (err && err.status === 401 && handleAuthExpired()) return;
          bootstrapAdminConsole(true);
        });
      });
    }
    loadAdminConsole();
    var adminQueueRetryBtn = document.getElementById('adminQueueRetryBtn');
    if (adminQueueRetryBtn) adminQueueRetryBtn.addEventListener('click', loadAdminConsole);

    // The `storage` listener is gone with the localStorage ticket store; the
    // poll is now the only way this console notices a change made elsewhere.
    setInterval(function () {
      fetchTickets(null, applyRemoteAdminUpdate);
    }, 4000);

    // Once-a-minute SLA refresh — see the matching block in the agent queue.
    setInterval(function () {
      if (!adminTickets.length) return;
      renderAdminStats(); renderAdminList();
      var t = adminTickets.filter(function (x) { return x.id === adminSelectedId; })[0];
      if (t) renderSlaBox(document.getElementById('adminDashSla'), t);
    }, 60000);

    // ---- Tabs: Tickets / Agents / Audit Logs / Reports ----
    document.querySelectorAll('.admin-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        document.querySelectorAll('.admin-tab').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        var tab = btn.dataset.tab;
        document.getElementById('adminTicketsPanel').style.display = tab === 'tickets' ? '' : 'none';
        document.getElementById('adminAgentsPanel').style.display = tab === 'agents' ? '' : 'none';
        document.getElementById('adminAuditPanel').style.display = tab === 'audit' ? '' : 'none';
        document.getElementById('adminReportsPanel').style.display = tab === 'reports' ? '' : 'none';
        document.getElementById('adminHelpPanel').style.display = tab === 'help' ? '' : 'none';
        if (tab === 'agents') renderAgentDirectory();
        if (tab === 'audit') loadAuditFacets(function () { loadAuditLogs(); });
        if (tab === 'reports') loadReportSummary();
        if (tab === 'help') loadAccountHelp();
      });
    });

    // ---- Account Help tab: "can't remember my email" requests ----
    var accountHelpStatus = 'open';

    function setAccountHelpOpenCount(n) {
      var badge = document.getElementById('accountHelpOpenCount');
      badge.textContent = n;
      badge.style.display = n ? '' : 'none';
    }

    function updateAccountHelp(id, body) {
      return fetch(API_BASE + '/api/account-help/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify(body)
      }).then(function (response) {
        if (response.status === 401 && handleAuthExpired()) return new Promise(function () {});
        return response.json().catch(function () { return {}; }).then(function (data) {
          if (!response.ok) throw new Error(data.error || 'Unable to update this request.');
          return data;
        });
      });
    }

    function renderAccountHelpRequest(r) {
      var card = document.createElement('div');
      card.className = 'help-request' + (r.status === 'resolved' ? ' resolved' : '');

      var facts = [
        ['Contact email', r.contact_email],
        ['Phone', r.phone],
        ['Organization', r.organization]
      ].filter(function (f) { return f[1]; });

      var matches = r.possible_matches || [];
      var matchesHtml = matches.length
        ? matches.map(function (m) {
            return '<div class="help-match">' +
              '<span class="history-id">' + escapeHtml(m.id) + '</span>' +
              '<strong>' + escapeHtml(m.full_name) + '</strong>' +
              '<span>' + escapeHtml(m.email) + '</span>' +
              (m.phone ? '<span>' + escapeHtml(m.phone) + '</span>' : '') +
              (m.organization ? '<span>' + escapeHtml(m.organization) + '</span>' : '') +
              '<span class="history-chip">' + escapeHtml(m.ticket_count) + ' ticket' + (Number(m.ticket_count) === 1 ? '' : 's') + '</span>' +
              (r.status === 'open'
                ? '<button class="btn-ghost btn-small help-notify" type="button" data-user-id="' + escapeHtml(m.id) + '">Send sign-in details</button>'
                : '') +
            '</div>';
          }).join('')
        : '<p class="help-none">No customer shares this name, email or phone. Search the Tickets tab by other details they gave.</p>';

      card.innerHTML =
        '<div class="help-head">' +
          '<div>' +
            '<p class="history-id">#' + escapeHtml(r.id) + ' · ' + escapeHtml(new Date(r.created_at).toLocaleString()) + '</p>' +
            '<p class="history-subject">' + escapeHtml(r.full_name) + '</p>' +
          '</div>' +
          '<span class="history-status">' + (r.status === 'resolved' ? 'Resolved' : 'Open') + '</span>' +
        '</div>' +
        '<div class="history-meta">' +
          facts.map(function (f) { return '<span class="history-chip">' + escapeHtml(f[0]) + ': ' + escapeHtml(f[1]) + '</span>'; }).join('') +
        '</div>' +
        (r.details ? '<p class="help-details">' + escapeHtml(r.details) + '</p>' : '') +
        '<p class="help-label">Possible matches</p>' +
        '<div class="help-matches">' + matchesHtml + '</div>' +
        (r.status === 'resolved'
          ? '<p class="help-resolution">Resolved' + (r.resolved_by_name ? ' by ' + escapeHtml(r.resolved_by_name) : '') +
              (r.resolved_at ? ' on ' + escapeHtml(new Date(r.resolved_at).toLocaleString()) : '') +
              (r.resolution_note ? ': ' + escapeHtml(r.resolution_note) : '.') + '</p>' +
            '<div class="action-row"><button class="btn-ghost btn-inline help-reopen" type="button">Reopen</button></div>'
          : '<div class="field" style="margin:14px 0 10px;">' +
              '<label>Resolution note <span class="opt">(optional)</span></label>' +
              '<textarea class="help-note" maxlength="1000" placeholder="e.g. Emailed them: account is under j•••@example.com"></textarea>' +
            '</div>' +
            '<div class="err help-err"></div>' +
            '<div class="action-row"><button class="btn-amber btn-inline help-resolve" type="button">Mark resolved</button></div>');

      var errEl = card.querySelector('.help-err');
      var resolveBtn = card.querySelector('.help-resolve');
      var reopenBtn = card.querySelector('.help-reopen');
      var actionBtn = resolveBtn || reopenBtn;
      actionBtn.addEventListener('click', function () {
        actionBtn.disabled = true;
        if (errEl) errEl.style.display = 'none';
        var body = resolveBtn
          ? { status: 'resolved', note: card.querySelector('.help-note').value.trim() }
          : { status: 'open' };
        updateAccountHelp(r.id, body)
          .then(function () { loadAccountHelp(); })
          .catch(function (err) {
            actionBtn.disabled = false;
            if (errEl) { errEl.textContent = err.message; errEl.style.display = 'block'; }
            else alert(err.message);
          });
      });

      // POST /:id/notify emails the matched account its sign-in reminder
      // (plus a masked pointer to the requester's contact address) and
      // resolves the request.
      card.querySelectorAll('.help-notify').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var m = matches.filter(function (x) { return x.id === btn.dataset.userId; })[0];
          if (!m) return;
          var msg = 'Email ' + m.full_name + ' at ' + m.email + ' to remind them this is their sign-in email?' +
            (m.email.toLowerCase() !== r.contact_email ? '\n\n' + r.contact_email + ' will be told to check that inbox (shown masked).' : '') +
            '\n\nThe request will be marked resolved.';
          if (!confirm(msg)) return;

          btn.disabled = true;
          btn.textContent = 'Sending…';
          if (errEl) errEl.style.display = 'none';
          fetch(API_BASE + '/api/account-help/' + encodeURIComponent(r.id) + '/notify', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
            body: JSON.stringify({ user_id: m.id })
          })
            .then(function (response) {
              if (response.status === 401 && handleAuthExpired()) return new Promise(function () {});
              return response.json().catch(function () { return {}; }).then(function (data) {
                if (!response.ok) throw new Error(data.error || 'Unable to send the email.');
              });
            })
            .then(function () { loadAccountHelp(); })
            .catch(function (err) {
              btn.disabled = false;
              btn.textContent = 'Send sign-in details';
              if (errEl) { errEl.textContent = err.message; errEl.style.display = 'block'; }
            });
        });
      });
      return card;
    }

    function loadAccountHelp() {
      var listEl = document.getElementById('accountHelpList');
      fetch(API_BASE + '/api/account-help?status=' + encodeURIComponent(accountHelpStatus), { headers: authHeaders() })
        .then(function (response) {
          if (!response.ok) {
            if (response.status === 401 && handleAuthExpired()) return null;
            throw new Error('failed to load account help requests');
          }
          return response.json();
        })
        .then(function (data) {
          if (!data) return;
          setAccountHelpOpenCount(data.open_count);
          listEl.innerHTML = '';
          if (!data.rows.length) {
            listEl.innerHTML = '<p class="queue-no-results">' +
              (accountHelpStatus === 'open' ? 'No open requests.' : 'No requests to show.') + '</p>';
            return;
          }
          data.rows.forEach(function (r) { listEl.appendChild(renderAccountHelpRequest(r)); });
        })
        .catch(function (err) {
          console.error('Account help load error:', err);
          listEl.innerHTML = '<p class="queue-no-results">Couldn’t load account help requests. Try again in a moment.</p>';
        });
    }

    document.getElementById('accountHelpStatusFilter').addEventListener('change', function (e) {
      accountHelpStatus = e.target.value;
      loadAccountHelp();
    });

    // Fill the tab's open-count badge on load, so new requests are noticed
    // without opening the tab.
    loadAccountHelp();

    // ---- Agents: directory list + create ----
    function ticketCountFor(name) {
      return adminTickets.filter(function (t) { return t.assignedAgent === name; }).length;
    }

    function renderAgentDirectory() {
      var agents = loadAgents();
      document.getElementById('adminAgentCountLabel').textContent = agents.length + (agents.length === 1 ? ' agent' : ' agents');
      document.getElementById('adminSidebarAgentCount').textContent = agents.length;
      var listEl = document.getElementById('adminAgentList');
      listEl.innerHTML = '';
      if (!agents.length) {
        listEl.innerHTML = '<p class="queue-no-results">No agents yet — add the first one above.</p>';
        return;
      }
      agents.forEach(function (a) {
        var row = document.createElement('div');
        row.className = 'history-row';
        var sourceLabel = a.createdBy === 'seed' ? 'Seed data' : (a.createdBy === 'admin' ? 'Added by admin' : 'Self sign-in');
        row.innerHTML =
          '<div class="history-main">' +
            '<p class="history-id">' + escapeHtml(a.id) + '</p>' +
            '<p class="history-subject">' + escapeHtml(a.name) + '</p>' +
          '</div>' +
          '<div class="history-meta">' +
            '<span class="history-chip">' + escapeHtml(a.email) + '</span>' +
            '<span class="history-chip">' + escapeHtml(ticketCountFor(a.name)) + ' assigned</span>' +
            '<span class="history-chip">' + sourceLabel + '</span>' +
            '<button class="btn-ghost btn-danger btn-small" type="button">Remove</button>' +
          '</div>';
        row.querySelector('.btn-danger').addEventListener('click', function () {
          var assigned = ticketCountFor(a.name);
          var msg = 'Remove ' + a.name + ' (' + a.email + ')? They will no longer be able to sign in.' +
            (assigned ? ' Their ' + assigned + ' assigned ticket(s) will be moved back to Unassigned.' : '');
          if (!confirm(msg)) return;

          var btn = this;
          btn.disabled = true;
          adminDelete('/api/agents/' + encodeURIComponent(a.id))
            .then(function () {
              refreshAgentDirectory(function () {
                renderAgentDirectory();
                renderAdminStats();
                populateAssigneeFilter();
              });
              // Pick up the unassigned tickets now rather than on the next poll.
              fetchTickets(null, applyRemoteAdminUpdate);
            })
            .catch(function (err) {
              btn.disabled = false;
              alert(err.message || 'Unable to remove this agent.');
            });
        });
        listEl.appendChild(row);
      });
    }
    renderAgentDirectory();

    document.getElementById('addAgentBtn').addEventListener('click', function () {
      var nameField = document.getElementById('newAgentName');
      var emailField = document.getElementById('newAgentEmail');
      var nameWrap = document.getElementById('f-newAgentName');
      var emailWrap = document.getElementById('f-newAgentEmail');
      var emailErr = document.getElementById('err-newAgentEmail');
      emailErr.textContent = 'Enter a valid work email.';
      var valid = true;

      if (!nameField.value.trim()) { nameWrap.classList.add('invalid'); valid = false; }
      else { nameWrap.classList.remove('invalid'); }

      var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailField.value.trim());
      if (!emailOk) { emailWrap.classList.add('invalid'); valid = false; }
      else { emailWrap.classList.remove('invalid'); }

      if (valid) {
        // Client-side dupe check against the cached directory for instant feedback;
        // the server enforces this too (409) as the source of truth below.
        var agents = loadAgents();
        var dupe = agents.some(function (a) { return a.email.toLowerCase() === emailField.value.trim().toLowerCase(); });
        if (dupe) {
          emailWrap.classList.add('invalid');
          emailErr.textContent = 'An agent with this email already exists.';
          valid = false;
        }
      }

      if (!valid) return;

      var addAgentBtnEl = document.getElementById('addAgentBtn');
      addAgentBtnEl.disabled = true;

      fetch(API_BASE + '/api/agents', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({
          full_name: nameField.value.trim(),
          email: emailField.value.trim(),
          created_by: 'admin'
        })
      })
        .then(function (response) {
          return response.json().then(function (data) {
            if (!response.ok) throw new Error(data.error || 'Unable to add this agent.');
            return data;
          });
        })
        .then(function () {
          nameField.value = '';
          emailField.value = '';
          refreshAgentDirectory(function () {
            renderAgentDirectory();
            renderAdminStats();
          });
        })
        .catch(function (err) {
          emailWrap.classList.add('invalid');
          emailErr.textContent = err.message || 'Unable to add this agent.';
        })
        .finally(function () {
          addAgentBtnEl.disabled = false;
        });
    });

    // ---- Audit Logs tab ----
    var auditPage = 1;
    var auditPageSize = 25;
    var auditTotal = 0;
    var auditFilters = { q: '', actor_type: '', action: '', from: '', to: '' };

    function auditQueryString(extra) {
      var params = Object.assign({}, auditFilters, extra || {});
      return Object.keys(params)
        .filter(function (k) { return params[k]; })
        .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
        .join('&');
    }

    function humanizeAction(action) {
      if (!action) return '—';
      return action.replace(/[._]/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function renderAuditLogList(rows) {
      var listEl = document.getElementById('auditLogList');
      listEl.innerHTML = '';
      if (!rows.length) {
        listEl.innerHTML = '<p class="queue-no-results">No audit log entries match your search or filters.</p>';
        return;
      }
      rows.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'history-row';
        var when = new Date(r.created_at).toLocaleString();
        var actorLabel = (r.actor_name || r.actor_id || 'Unknown') + (r.actor_type ? ' (' + r.actor_type + ')' : '');
        var entityLabel = r.entity_type ? (r.entity_type + (r.entity_id ? ' ' + r.entity_id : '')) : '';
        row.innerHTML =
          '<div class="history-main">' +
            '<p class="history-id">' + escapeHtml(when) + '</p>' +
            '<p class="history-subject">' + escapeHtml(humanizeAction(r.action)) + '</p>' +
          '</div>' +
          '<div class="history-meta">' +
            '<span class="history-chip">' + escapeHtml(actorLabel) + '</span>' +
            (entityLabel ? '<span class="history-chip">' + escapeHtml(entityLabel) + '</span>' : '') +
          '</div>';
        listEl.appendChild(row);
      });
    }

    function loadAuditLogs() {
      var qs = auditQueryString({ page: auditPage, page_size: auditPageSize });
      fetch(API_BASE + '/api/audit-logs?' + qs, { headers: authHeaders() })
        .then(function (response) {
          if (!response.ok) {
            if (response.status === 401 && handleAuthExpired()) return null;
            throw new Error('failed to load audit logs');
          }
          return response.json();
        })
        .then(function (data) {
          if (!data) return;
          auditTotal = data.total;
          renderAuditLogList(data.rows);
          var maxPage = Math.max(1, Math.ceil(auditTotal / auditPageSize));
          document.getElementById('auditPageInfo').textContent = 'Page ' + auditPage + ' of ' + maxPage + ' · ' + auditTotal + ' entries';
          document.getElementById('auditPrevBtn').disabled = auditPage <= 1;
          document.getElementById('auditNextBtn').disabled = auditPage >= maxPage;
        })
        .catch(function (err) {
          console.error('Audit log load error:', err);
          document.getElementById('auditLogList').innerHTML = '<p class="queue-no-results">Couldn’t load audit logs. Try again in a moment.</p>';
        });
    }

    // Action values come from whatever's actually been logged so far,
    // rather than a hardcoded list that'd drift as new actions get
    // instrumented server-side.
    function loadAuditFacets(cb) {
      fetch(API_BASE + '/api/audit-logs/facets', { headers: authHeaders() })
        .then(function (response) { return response.ok ? response.json() : { actions: [] }; })
        .then(function (data) {
          var sel = document.getElementById('auditActionFilter');
          var current = sel.value;
          Array.prototype.slice.call(sel.querySelectorAll('option[data-action-option]')).forEach(function (o) { o.remove(); });
          (data.actions || []).forEach(function (a) {
            var opt = document.createElement('option');
            opt.value = a; opt.textContent = humanizeAction(a);
            opt.setAttribute('data-action-option', '1');
            sel.appendChild(opt);
          });
          sel.value = current;
        })
        .catch(function () {})
        .then(function () { if (cb) cb(); });
    }

    document.getElementById('auditSearchInput').addEventListener('input', function (e) {
      auditFilters.q = e.target.value; auditPage = 1; loadAuditLogs();
    });
    document.getElementById('auditActorFilter').addEventListener('change', function (e) {
      auditFilters.actor_type = e.target.value; auditPage = 1; loadAuditLogs();
    });
    document.getElementById('auditActionFilter').addEventListener('change', function (e) {
      auditFilters.action = e.target.value; auditPage = 1; loadAuditLogs();
    });
    document.getElementById('auditFromInput').addEventListener('change', function (e) {
      auditFilters.from = e.target.value; auditPage = 1; loadAuditLogs();
    });
    document.getElementById('auditToInput').addEventListener('change', function (e) {
      auditFilters.to = e.target.value; auditPage = 1; loadAuditLogs();
    });
    document.getElementById('auditClearFilters').addEventListener('click', function () {
      auditFilters = { q: '', actor_type: '', action: '', from: '', to: '' };
      document.getElementById('auditSearchInput').value = '';
      document.getElementById('auditActorFilter').value = '';
      document.getElementById('auditActionFilter').value = '';
      document.getElementById('auditFromInput').value = '';
      document.getElementById('auditToInput').value = '';
      auditPage = 1;
      loadAuditLogs();
    });
    document.getElementById('auditPrevBtn').addEventListener('click', function () {
      if (auditPage > 1) { auditPage -= 1; loadAuditLogs(); }
    });
    document.getElementById('auditNextBtn').addEventListener('click', function () {
      auditPage += 1; loadAuditLogs();
    });

    document.getElementById('auditExportBtn').addEventListener('click', function () {
      var btn = document.getElementById('auditExportBtn');
      var format = document.getElementById('auditExportFormat').value;
      var qs = auditQueryString({ type: 'audit-logs', format: format });
      btn.disabled = true;
      downloadReportFile(API_BASE + '/api/reports/export?' + qs, 'audit-logs-report.' + format)
        .catch(function (err) { alert(err.message || 'Unable to generate this report.'); })
        .finally(function () { btn.disabled = false; });
    });

    // ---- Reports tab ----
    function fmtHours(h) {
      if (h === null || h === undefined) return '—';
      if (h < 1) return Math.round(h * 60) + ' min';
      return h.toFixed(1) + ' hrs';
    }

    function renderBreakdownList(elId, rows, labelKey) {
      var listEl = document.getElementById(elId);
      listEl.innerHTML = '';
      if (!rows.length) {
        listEl.innerHTML = '<p class="queue-no-results">No data for this range.</p>';
        return;
      }
      rows.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'history-row';
        row.innerHTML =
          '<div class="history-main"><p class="history-subject">' + escapeHtml(r[labelKey]) + '</p></div>' +
          '<div class="history-meta"><span class="history-chip">' + escapeHtml(r.count) + '</span></div>';
        listEl.appendChild(row);
      });
    }

    function renderAgentWorkload(rows) {
      var listEl = document.getElementById('reportByAgent');
      listEl.innerHTML = '';
      if (!rows.length) {
        listEl.innerHTML = '<p class="queue-no-results">No agents yet.</p>';
        return;
      }
      rows.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'history-row';
        row.innerHTML =
          '<div class="history-main"><p class="history-subject">' + escapeHtml(r.agent_name) + '</p></div>' +
          '<div class="history-meta">' +
            '<span class="history-chip">' + escapeHtml(r.open_count) + ' open</span>' +
            '<span class="history-chip">' + escapeHtml(r.resolved_count) + ' resolved</span>' +
          '</div>';
        listEl.appendChild(row);
      });
    }

    function fmtPct(p) { return p === null || p === undefined ? '—' : p + '%'; }

    function renderSlaReport(sla) {
      if (!sla) return;
      document.getElementById('reportSlaResolution').textContent = fmtPct(sla.resolution.compliance_pct);
      document.getElementById('reportSlaBreached').textContent = sla.resolution.breached;
      document.getElementById('reportSlaOpenBreached').textContent = sla.open_breached;

      var listEl = document.getElementById('reportSlaByPriority');
      listEl.innerHTML = '';
      if (!sla.by_priority.length) {
        listEl.innerHTML = '<p class="queue-no-results">No data for this range.</p>';
        return;
      }
      sla.by_priority.forEach(function (r) {
        var row = document.createElement('div');
        row.className = 'history-row';
        row.innerHTML =
          '<div class="history-main"><p class="history-subject">' + escapeHtml(r.priority) + '</p></div>' +
          '<div class="history-meta">' +
            '<span class="history-chip">Resolution ' + escapeHtml(fmtPct(r.resolution_compliance_pct)) + '</span>' +
            (r.resolution_breached ? '<span class="history-chip sla-chip sla-breached">' + escapeHtml(r.resolution_breached) + ' breached</span>' : '') +
          '</div>';
        listEl.appendChild(row);
      });
    }

    function loadReportSummary() {
      var from = document.getElementById('reportFromInput').value;
      var to = document.getElementById('reportToInput').value;
      var params = [];
      if (from) params.push('from=' + encodeURIComponent(from));
      if (to) params.push('to=' + encodeURIComponent(to));
      fetch(API_BASE + '/api/reports/summary' + (params.length ? '?' + params.join('&') : ''), { headers: authHeaders() })
        .then(function (response) {
          if (!response.ok) {
            if (response.status === 401 && handleAuthExpired()) return null;
            throw new Error('failed to load report summary');
          }
          return response.json();
        })
        .then(function (data) {
          if (!data) return;
          document.getElementById('reportStatTotal').textContent = data.total;
          document.getElementById('reportStatResolution').textContent = fmtHours(data.avg_resolution_hours);
          document.getElementById('reportStatCsat').textContent = data.csat.average !== null ? data.csat.average + ' / 5' : '—';
          document.getElementById('reportStatCsatCount').textContent = data.csat.responses;
          renderSlaReport(data.sla);
          renderBreakdownList('reportByStatus', data.by_status, 'status');
          renderBreakdownList('reportByCategory', data.by_category, 'category');
          renderBreakdownList('reportByPriority', data.by_priority, 'priority');
          renderAgentWorkload(data.by_agent);
        })
        .catch(function (err) {
          console.error('Report summary load error:', err);
        });
    }

    document.getElementById('reportRefreshBtn').addEventListener('click', loadReportSummary);

    document.getElementById('reportExportBtn').addEventListener('click', function () {
      var btn = document.getElementById('reportExportBtn');
      var format = document.getElementById('reportExportFormat').value;
      var status = document.getElementById('reportExportStatus').value;
      var from = document.getElementById('reportFromInput').value;
      var to = document.getElementById('reportToInput').value;
      var params = ['type=tickets', 'format=' + format];
      if (status) params.push('status=' + encodeURIComponent(status));
      if (from) params.push('from=' + encodeURIComponent(from));
      if (to) params.push('to=' + encodeURIComponent(to));
      btn.disabled = true;
      downloadReportFile(API_BASE + '/api/reports/export?' + params.join('&'), 'tickets-report.' + format)
        .catch(function (err) { alert(err.message || 'Unable to generate this report.'); })
        .finally(function () { btn.disabled = false; });
    });
  }

});
