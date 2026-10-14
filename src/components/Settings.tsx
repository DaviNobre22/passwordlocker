import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  vaultPath: string;
  /** Receives the new recovery code to show on the verify screen. */
  onRotation: (code: string) => void;
  /** Opens the restore screen, which replaces the vault with a backup. */
  onRestore: () => void;
  onBack: () => void;
  onLock: () => void;
}

export function Settings({ vaultPath, onRotation, onRestore, onBack, onLock }: Props) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function changePassword(event: React.FormEvent) {
    event.preventDefault();
    setMessage("");
    if (next !== confirm) {
      setError("The two new passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.changeMasterPassword(current, next);
      setMessage("Master password changed.");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setCurrent("");
      setNext("");
      setConfirm("");
      setBusy(false);
    }
  }

  async function newRecoveryCode() {
    setMessage("");
    setError("");
    try {
      onRotation(await api.beginRecoveryRotation());
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function exportBackup() {
    setMessage("");
    setError("");
    setBusy(true);
    try {
      const saved = await api.exportBackup();
      if (saved !== null) setMessage(`Backup saved to ${saved}`);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="card wide">
      <h1>Settings</h1>

      <section>
        <h2>Vault file</h2>
        <p className="mono path">{vaultPath}</p>
      </section>

      <section>
        <h2>Change master password</h2>
        <form onSubmit={changePassword}>
          <label>
            Current password
            <input
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
            />
          </label>
          <label>
            New password
            <input
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <label>
            Confirm new password
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </label>
          <button type="submit" disabled={busy || current === "" || next === ""}>
            Change password
          </button>
        </form>
      </section>

      <section>
        <h2>Recovery code</h2>
        <p>Make a new recovery code. The old one stops working.</p>
        <button type="button" onClick={newRecoveryCode}>
          New recovery code
        </button>
      </section>

      <section>
        <h2>Backup</h2>
        <p>
          Save a copy of your vault to a file, for example on a USB stick. The copy is encrypted:
          on another PC it opens with your master password and your recovery code.
        </p>
        <button type="button" onClick={exportBackup} disabled={busy}>
          Export backup...
        </button>
        <p>
          Restoring replaces the vault on this PC with a backup file. You will need the master
          password and recovery code of that backup.
        </p>
        <button type="button" onClick={onRestore} disabled={busy}>
          Restore from a backup file...
        </button>
      </section>

      {message && <p className="success">{message}</p>}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <div className="row">
        <button type="button" onClick={onBack}>
          Back
        </button>
        <button type="button" onClick={onLock}>
          Lock now
        </button>
      </div>
    </main>
  );
}
