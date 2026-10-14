import { useState } from "react";
import { errorText } from "../api";

interface Props {
  title: string;
  code: string;
  /** Called with the code the user typed back. Rejects with a message if wrong. */
  onConfirm: (typed: string) => Promise<void>;
  onCancel: () => void;
}

/**
 * Shows the recovery code and makes the user prove they saved it by typing it
 * back. Used when creating the vault and when replacing the recovery code.
 * The code exists only in this component's props, so it disappears from the
 * window as soon as the parent drops it.
 */
export function RecoveryCode({ title, code, onConfirm, onCancel }: Props) {
  const [written, setWritten] = useState(false);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onConfirm(typed);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  }

  return (
    <main className="card">
      <div className="no-print">
        <h1>{title}</h1>
        <p>
          This code is the way back into your vault if you lose this PC or its device link.
          Write it down or print it and keep it somewhere safe. It is shown only now.
        </p>
      </div>

      {/* Hidden while typing it back, so the check proves it was written down
          rather than copied from the screen. Unticking the box shows it again. */}
      {!written && (
        <section className="recovery-code" aria-label="Recovery code">
          <p className="print-only">
            Password Locker recovery code. Keep this paper somewhere safe, away from your
            computer. Anyone with this code and your master password can open your vault.
          </p>
          <code>
            {code.split("-").map((group, i) => (
              <span key={i} className="code-group">
                {i > 0 && "-"}
                {group}
              </span>
            ))}
          </code>
        </section>
      )}

      <form className="no-print" onSubmit={submit}>
        {!written && (
          <button type="button" onClick={() => window.print()}>
            Print
          </button>
        )}

        <label className="check">
          <input
            type="checkbox"
            checked={written}
            onChange={(e) => {
              setWritten(e.target.checked);
              setTyped("");
            }}
          />
          I have written it down
        </label>

        {written && (
          <label>
            Type the code back to confirm
            <input
              className="mono"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              autoFocus
            />
          </label>
        )}

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}

        <div className="row">
          <button
            type="submit"
            className="primary"
            disabled={!written || typed.trim() === "" || busy}
          >
            Confirm
          </button>
          <button type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        </div>
      </form>
    </main>
  );
}
