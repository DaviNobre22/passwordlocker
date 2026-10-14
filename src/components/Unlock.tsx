import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  onUnlocked: () => void;
}

export function Unlock({ onUnlocked }: Props) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    let ok = false;
    try {
      if (useRecovery) {
        await api.unlockWithRecovery(password, code);
      } else {
        await api.unlock(password);
      }
      ok = true;
    } catch (e) {
      setError(errorText(e));
    } finally {
      // Cleared whether it worked or not.
      setPassword("");
      setCode("");
      setBusy(false);
    }
    if (ok) onUnlocked();
  }

  return (
    <main className="card">
      <h1>Password Locker</h1>
      <form onSubmit={submit}>
        <label>
          Master password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            autoFocus
          />
        </label>
        {useRecovery && (
          <label>
            Recovery code
            <input
              className="mono"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="primary" disabled={busy || password === ""}>
          {busy ? "Unlocking..." : "Unlock"}
        </button>
      </form>
      <p>
        <button type="button" className="link" onClick={() => setUseRecovery(!useRecovery)}>
          {useRecovery ? "Use this PC's device key instead" : "Use recovery code instead"}
        </button>
      </p>
    </main>
  );
}
