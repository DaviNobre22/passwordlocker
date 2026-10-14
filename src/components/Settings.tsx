import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  vaultPath: string;
  /** Receives the new recovery code to show on the verify screen. */
  onRotation: (code: string) => void;
  onBack: () => void;
  onLock: () => void;
}

export function Settings({ vaultPath, onRotation, onBack, onLock }: Props) {
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
