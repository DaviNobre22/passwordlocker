import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  /** True when a vault already exists and would be replaced. */
  replacing: boolean;
  onRestored: () => void;
  onCancel: () => void;
}

/**
 * Restore from a backup file. Rust shows the file dialog and remembers the
 * chosen file; the window only sees its path, for display. The password and
 * recovery code are the ones that belong to the backup.
 */
export function RestoreBackup({ replacing, onRestored, onCancel }: Props) {
  const [file, setFile] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function pick() {
    setError("");
    try {
      const picked = await api.pickBackupFile();
      if (picked !== null) setFile(picked);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function cancel() {
    // Forget the chosen file in Rust as well.
    await api.cancelRestore().catch(() => {});
    onCancel();
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    let ok = false;
    try {
      await api.restoreBackup(password, code);
      ok = true;
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPassword("");
      setCode("");
      setBusy(false);
    }
    if (ok) onRestored();
  }

  const ready = file !== null && password !== "" && code.trim() !== "" && (!replacing || confirmed);

  return (
    <main className="card">
      <h1>Restore from a backup</h1>
      <p>
        Choose a backup file (.pwlk). To open it you need the master password and the recovery
        code that were in use when the backup was made.
      </p>
      <p>
        <button type="button" onClick={pick} disabled={busy}>
          {file === null ? "Choose backup file..." : "Choose a different file..."}
        </button>
      </p>
      {file !== null && <p className="mono path">{file}</p>}

      {file !== null && (
        <form onSubmit={submit}>
          <label>
            Master password of the backup
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              autoFocus
            />
          </label>
          <label>
            Recovery code of the backup
            <input
              className="mono"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          {replacing && (
            <>
              <p className="hint">
                This replaces your current vault with the backup. A copy of the current vault is
                kept next to it, in a file whose name contains "before-restore", but entries
                added since the backup was made will only be in that copy.
              </p>
              <label className="check">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                />
                I understand that my current vault will be replaced
              </label>
            </>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <button type="submit" className="primary" disabled={busy || !ready}>
            {busy ? "Restoring..." : "Restore"}
          </button>
        </form>
      )}

      {file === null && error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <p>
        <button type="button" className="link" onClick={cancel} disabled={busy}>
          Cancel
        </button>
      </p>
    </main>
  );
}
