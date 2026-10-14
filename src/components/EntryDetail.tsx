import { useEffect, useState } from "react";
import { api, errorText, type EntrySummary, type PastPassword } from "../api";

/** How long a revealed password stays visible. */
const REVEAL_SECONDS = 15;
/** Matches the clipboard timer in src-tauri/src/clipboard.rs. */
const CLEAR_SECONDS = 30;

interface Props {
  entry: EntrySummary;
  onEdit: () => void;
  onDeleted: () => void;
}

/**
 * The right-hand panel for one entry. The parent gives it `key={entry.id}`,
 * so picking another entry unmounts this component and every revealed secret
 * in its state is dropped with it.
 */
export function EntryDetail({ entry, onEdit, onDeleted }: Props) {
  const [password, setPassword] = useState<string | null>(null);
  const [notes, setNotes] = useState<string | null>(null);
  const [history, setHistory] = useState<PastPassword[] | null>(null);
  const [copied, setCopied] = useState<"username" | "password" | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState("");

  // Hide the password again after a while. Re-runs (and restarts the timer)
  // each time a new password is revealed; the cleanup cancels it on unmount.
  useEffect(() => {
    if (password === null) return;
    const timer = window.setTimeout(() => setPassword(null), REVEAL_SECONDS * 1000);
    return () => window.clearTimeout(timer);
  }, [password]);

  useEffect(() => {
    if (copied !== "password") return;
    const timer = window.setTimeout(() => setCopied(null), CLEAR_SECONDS * 1000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  async function run(action: () => Promise<void>) {
    setError("");
    try {
      await action();
    } catch (e) {
      setError(errorText(e));
    }
  }

  const togglePassword = () =>
    run(async () => {
      setPassword(password === null ? await api.revealPassword(entry.id) : null);
    });

  const toggleNotes = () =>
    run(async () => {
      setNotes(notes === null ? await api.revealNotes(entry.id) : null);
    });

  const toggleHistory = () =>
    run(async () => {
      setHistory(history === null ? await api.revealPasswordHistory(entry.id) : null);
    });

  const copy = (what: "username" | "password") =>
    run(async () => {
      if (what === "username") await api.copyUsername(entry.id);
      else await api.copyPassword(entry.id);
      setCopied(what);
    });

  const remove = () =>
    run(async () => {
      await api.deleteEntry(entry.id);
      onDeleted();
    });

  return (
    <section className="detail" aria-label="Entry details">
      <h2>{entry.title}</h2>

      <dl>
        <dt>Username</dt>
        <dd>
          <span>{entry.username || "-"}</span>
          {entry.username && (
            <button type="button" onClick={() => copy("username")}>
              {copied === "username" ? "Copied" : "Copy"}
            </button>
          )}
        </dd>

        <dt>Password</dt>
        <dd>
          <span className="mono">{password ?? "••••••••"}</span>
          <button type="button" onClick={togglePassword}>
            {password === null ? "Reveal" : "Hide"}
          </button>
          <button type="button" onClick={() => copy("password")}>
            Copy
          </button>
        </dd>
        {copied === "password" && (
          <dd className="hint">Copied &mdash; clears in {CLEAR_SECONDS} s</dd>
        )}

        <dt>Website</dt>
        <dd>
          <span>{entry.url || "-"}</span>
        </dd>

        <dt>Tags</dt>
        <dd>
          {entry.tags.length === 0 ? (
            <span>-</span>
          ) : (
            entry.tags.map((tag) => (
              <span key={tag} className="tag">
                {tag}
              </span>
            ))
          )}
        </dd>
      </dl>

      <div className="row">
        <button type="button" onClick={toggleNotes}>
          {notes === null ? "Show notes" : "Hide notes"}
        </button>
        <button type="button" onClick={toggleHistory}>
          {history === null ? "Show history" : "Hide history"}
        </button>
      </div>

      {notes !== null && <pre className="notes">{notes || "(no notes)"}</pre>}

      {history !== null &&
        (history.length === 0 ? (
          <p className="hint">No earlier passwords.</p>
        ) : (
          <ul className="history">
            {history.map((past, index) => (
              <li key={index}>
                <span className="mono">{past.password}</span>
                <span className="hint">
                  replaced {new Date(past.replaced_at * 1000).toLocaleDateString()}
                </span>
              </li>
            ))}
          </ul>
        ))}

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <div className="row">
        <button type="button" onClick={onEdit}>
          Edit
        </button>
        {confirmDelete ? (
          <>
            <span>Delete this entry?</span>
            <button type="button" className="danger" onClick={remove}>
              Yes, delete
            </button>
            <button type="button" onClick={() => setConfirmDelete(false)}>
              No
            </button>
          </>
        ) : (
          <button type="button" className="danger" onClick={() => setConfirmDelete(true)}>
            Delete
          </button>
        )}
      </div>
    </section>
  );
}
