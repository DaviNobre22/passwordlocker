import { useState } from "react";
import { api, errorText, type EntrySummary } from "../api";
import { Generator } from "./Generator";

interface Props {
  /** The entry being edited, or null when creating a new one. */
  entry: EntrySummary | null;
  onDone: () => void;
}

export function EntryForm({ entry, onDone }: Props) {
  const editing = entry !== null;
  const [title, setTitle] = useState(entry?.title ?? "");
  const [username, setUsername] = useState(entry?.username ?? "");
  const [url, setUrl] = useState(entry?.url ?? "");
  const [tags, setTags] = useState(entry?.tags.join(", ") ?? "");
  // When editing, these start empty and an empty value means "unchanged":
  // the window never fetches the stored secrets just to put them in a form.
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const draft = {
      title,
      username,
      url,
      tags: tags.split(",").map((tag) => tag.trim()).filter((tag) => tag !== ""),
      password: editing && password === "" ? null : password,
      notes: editing && notes === "" ? null : notes,
    };
    try {
      if (entry) await api.updateEntry(entry.id, draft);
      else await api.addEntry(draft);
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  }

  return (
    <main className="card wide">
      <h1>{editing ? "Edit entry" : "New entry"}</h1>
      <form onSubmit={submit}>
        <label>
          Title (required)
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
        </label>
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
        </label>

        <label>
          Password
          <span className="row">
            <input
              className="mono grow"
              type={showPassword ? "text" : "password"}
              value={password}
              placeholder={editing ? "unchanged" : ""}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            <button type="button" onClick={() => setShowPassword(!showPassword)}>
              {showPassword ? "Hide" : "Show"}
            </button>
            <button type="button" onClick={() => setShowGenerator(!showGenerator)}>
              Generate
            </button>
          </span>
        </label>
        {showGenerator && (
          <Generator
            onGenerated={(text) => {
              setPassword(text);
              setShowPassword(true);
            }}
          />
        )}

        <label>
          Website
          <input value={url} onChange={(e) => setUrl(e.target.value)} autoComplete="off" />
        </label>
        <label>
          Notes
          <textarea
            value={notes}
            placeholder={editing ? "unchanged" : ""}
            onChange={(e) => setNotes(e.target.value)}
            rows={4}
          />
        </label>
        <label>
          Tags (comma-separated)
          <input value={tags} onChange={(e) => setTags(e.target.value)} />
        </label>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="row">
          <button type="submit" className="primary" disabled={busy || title.trim() === ""}>
            Save
          </button>
          <button type="button" onClick={onDone} disabled={busy}>
            Cancel
          </button>
        </div>
      </form>
    </main>
  );
}
