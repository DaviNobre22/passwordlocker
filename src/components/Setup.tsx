import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  /** Receives the recovery code to show; the vault is not created yet. */
  onCode: (code: string) => void;
  /** Switches to restoring an existing backup instead of creating a vault. */
  onRestore: () => void;
}

export function Setup({ onCode, onRestore }: Props) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    let code: string | null = null;
    try {
      code = await api.beginSetup(password);
    } catch (e) {
      setError(errorText(e));
    } finally {
      // Rust keeps the password for the next step; the window must not.
      setPassword("");
      setConfirm("");
      setBusy(false);
    }
    if (code !== null) onCode(code);
  }

  return (
    <main className="card">
      <h1>Create your vault</h1>
      <p>
        Choose a master password. It protects everything, and it cannot be recovered if you
        forget it: the recovery code you get next replaces only this PC's device link.
      </p>
      <form onSubmit={submit}>
        <label>
          Master password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            autoFocus
          />
        </label>
        <p className="hint">
          At least 12 characters, and not easy to guess. Several unrelated words work well.
        </p>
        <label>
          Confirm master password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="primary" disabled={busy || password === ""}>
          Continue
        </button>
      </form>
      <p>
        <button type="button" className="link" onClick={onRestore} disabled={busy}>
          Restore from a backup file instead
        </button>
      </p>
    </main>
  );
}
