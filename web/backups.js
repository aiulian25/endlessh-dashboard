import { latestRequests, isAbortError } from './requests.js';
/* Backups: list, create, download, upload, restore and delete database
   snapshots. Rendered as a card inside Settings rather than as a page of its
   own — backing up is something you set up once and then leave alone, which
   belongs with the other things you manage rather than in the primary nav
   beside the pages you actually watch. */

import {
  api, esc, icon, toast, onRefresh, renderError, emptyState, confirmModal,
  fmtBytes, fmtRelative, fmtDateTime, API_BASE,
} from './app.js';

// The form field the upload handler reads the file from, and the ceiling it
// enforces. Both mirror the server: restoreUploadField and maxUploadBytes in
// internal/api. Checking the size here only saves the operator a long upload
// that would be refused at the end of it; the server is what enforces it.
const UPLOAD_FIELD = 'backup';
const MAX_UPLOAD_BYTES = 512 * 1024 * 1024;
const BACKUP_FILE_EXTENSION = '.db';

function backupRow(backup) {
  const href = `${API_BASE}/backups/${encodeURIComponent(backup.name)}`;
  return `
    <tr>
      <td class="mono strong">${esc(backup.name)}</td>
      <td class="mono num">${esc(fmtBytes(backup.size))}</td>
      <td><span title="${esc(fmtDateTime(backup.created_at))}">${esc(fmtRelative(backup.created_at))}</span></td>
      <td>
        <span class="row-actions">
          <a class="row-btn" href="${esc(href)}" download aria-label="Download ${esc(backup.name)}">${icon('download', 15)}</a>
          <button type="button" class="row-btn" data-restore="${esc(backup.name)}" aria-label="Restore ${esc(backup.name)}">${icon('restore', 15)}</button>
          <button type="button" class="row-btn danger" data-delete="${esc(backup.name)}" aria-label="Delete ${esc(backup.name)}">${icon('trash', 15)}</button>
        </span>
      </td>
    </tr>`;
}

// renderBackups fills the host element with the whole backups section. It owns
// its own loading, so the caller only has to give it somewhere to live.
export async function renderBackups(host, routeSignal) {
  const requests = latestRequests(routeSignal);
  host.innerHTML = `
    <div class="card" id="backups-card">
      <div class="card-head">
        <h2 class="card-title">Backups</h2>
        <span class="card-actions">
          <button type="button" class="btn btn-sm" id="backup-upload">${icon('upload', 15)} Restore from file</button>
          <button type="button" class="btn btn-sm btn-primary" id="backup-now">${icon('archive', 15)} Back up now</button>
        </span>
      </div>
      <div id="backups-body">
        <div class="card-pad"><div class="skeleton w60"></div></div>
      </div>
    </div>
    <input type="file" id="backup-file" class="sr-only" accept="${BACKUP_FILE_EXTENSION}"
           tabindex="-1" aria-hidden="true">`;

  const mount = host;
  const card = mount.querySelector('#backups-body');
  const createButton = mount.querySelector('#backup-now');
  const uploadButton = mount.querySelector('#backup-upload');
  const fileInput = mount.querySelector('#backup-file');

  const load = async () => {
    const request = requests.begin();
    if (!request.isCurrent()) return;
    try {
      const data = await api('/backups', { signal: request.signal });
      if (!request.isCurrent()) return;
      paint(data || []);
    } catch (error) {
      if (!request.isCurrent() || isAbortError(error)) return;
      if (error.status === 401) return;
      renderError(card, error, load);
    }
  };

  const paint = (backups) => {
    if (!backups.length) {
      card.innerHTML = emptyState({
        title: 'No backups yet',
        text: 'Create a snapshot before upgrading or changing machines. Backups are written on the server and can be downloaded from here.',
        actionLabel: 'Back up now',
        glyph: 'archive',
      });
      card.querySelector('[data-empty-action]').addEventListener('click', createBackup);
      return;
    }

    card.innerHTML = `
      <div class="table-wrap">
        <table class="tbl">
          <thead><tr>
            <th scope="col">Backup</th>
            <th scope="col" class="num">Size</th>
            <th scope="col">Created</th>
            <th scope="col"><span class="sr-only">Actions</span></th>
          </tr></thead>
          <tbody>${backups.map(backupRow).join('')}</tbody>
        </table>
      </div>`;

    card.querySelectorAll('[data-restore]').forEach((button) => {
      button.addEventListener('click', () => restoreBackup(button.dataset.restore));
    });
    card.querySelectorAll('[data-delete]').forEach((button) => {
      button.addEventListener('click', () => deleteBackup(button.dataset.delete));
    });
  };

  const createBackup = async () => {
    createButton.disabled = true;
    try {
      const backup = await api('/backups', { method: 'POST' });
      toast(`Backup ${backup.name} created (${fmtBytes(backup.size)}).`, 'success');
      await load();
    } catch (error) {
      if (error.status !== 401) toast(error.message, 'error');
    } finally {
      createButton.disabled = false;
    }
  };

  const restoreBackup = async (name) => {
    const ok = await confirmModal({
      title: 'Restore this backup?',
      message: `
        <p>Restoring <strong>${esc(name)}</strong> replaces the entire dashboard database: every machine, all collected history and the stored settings.</p>
        <p>The dashboard restarts to finish the restore, so it will be unreachable for a few seconds and you may need to sign in again.</p>
        <p><strong>Anything recorded since this backup was taken is lost.</strong></p>`,
      confirmLabel: 'Restore and restart',
    });
    if (!ok) return;
    try {
      const result = await api(`/backups/${encodeURIComponent(name)}/restore`, { method: 'POST' });
      toast((result && result.message) || 'Restore started. The dashboard is restarting.', 'success');
    } catch (error) {
      if (error.status !== 401) toast(error.message, 'error');
    }
  };

  // The counterpart to the download button on each row: it takes a file back,
  // which is the only way to recover when the server holds no backup to restore
  // from — a replaced volume, or a machine being rebuilt from a copy kept
  // elsewhere. The upload is staged and verified before anything is replaced,
  // so this is the same restart-and-restore flow as restoring a stored backup,
  // not a way to add a file to the list above.
  const uploadBackup = async (file) => {
    if (file.size > MAX_UPLOAD_BYTES) {
      toast(`That file is ${fmtBytes(file.size)}. The most that can be uploaded is ${fmtBytes(MAX_UPLOAD_BYTES)}.`, 'error');
      return;
    }

    const ok = await confirmModal({
      title: 'Restore from this file?',
      message: `
        <p>Restoring from <strong>${esc(file.name)}</strong> (${esc(fmtBytes(file.size))}) replaces the entire dashboard database: every machine, all collected history and the stored settings.</p>
        <p>The file is checked on the server first and refused if it is not a dashboard database, so nothing is replaced by a file that could not be restored.</p>
        <p>The dashboard restarts to finish the restore, so it will be unreachable for a few seconds and you may need to sign in again.</p>
        <p><strong>Anything recorded since this file was written is lost.</strong></p>`,
      confirmLabel: 'Restore and restart',
    });
    if (!ok) return;

    const payload = new FormData();
    payload.append(UPLOAD_FIELD, file);

    const uploadLabel = uploadButton.innerHTML;
    uploadButton.disabled = true;
    createButton.disabled = true;
    uploadButton.textContent = 'Uploading…';
    try {
      const result = await api('/backups/upload', { method: 'POST', body: payload });
      toast((result && result.message) || 'Upload accepted. The dashboard is restarting.', 'success');
    } catch (error) {
      if (error.status !== 401) toast(error.message, 'error');
    } finally {
      uploadButton.innerHTML = uploadLabel;
      uploadButton.disabled = false;
      createButton.disabled = false;
    }
  };

  const deleteBackup = async (name) => {
    const ok = await confirmModal({
      title: `Delete ${name}?`,
      message: '<p>The backup file is removed from the server. If you want to keep a copy, download it first.</p>',
      confirmLabel: 'Delete backup',
    });
    if (!ok) return;
    try {
      await api(`/backups/${encodeURIComponent(name)}`, { method: 'DELETE' });
      toast('Backup deleted.', 'success');
      await load();
    } catch (error) {
      if (error.status !== 401) toast(error.message, 'error');
    }
  };

  createButton.addEventListener('click', createBackup);
  uploadButton.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    const [file] = fileInput.files;
    // Read the file out before clearing, and clear either way: without this the
    // same file picked twice in a row raises no second change event, so a
    // cancelled or failed restore could not simply be retried.
    fileInput.value = '';
    if (file) uploadBackup(file);
  });

  onRefresh(load, requests.signal);
  await load();
}
