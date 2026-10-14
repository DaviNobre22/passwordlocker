import { useEffect, useState } from "react";
import { api, errorText, type EntrySummary } from "../api";
import { EntryDetail } from "./EntryDetail";

interface Props {
  onNew: () => void;
  onEdit: (entry: EntrySummary) => void;
  onSettings: () => void;
  onLock: () => void;
}

export function Main({ onNew, onEdit, onSettings, onLock }: Props) {
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Bumped after a delete to fetch the list again.
  const [version, setVersion] = useState(0);
  const [error, setError] = useState("");

  // Search as you type. The `cancelled` flag drops the answer of an older
  // request if a newer keystroke has already replaced it.
  useEffect(() => {
    let cancelled = false;
    api
      .listEntries(query)
      .then((found) => {
        if (!cancelled) setEntries(found);
      })
      .catch((e) => {
        if (!cancelled) setError(errorText(e));
      });
    return () => {
      cancelled = true;
    };
  }, [query, version]);

  const selected = entries.find((entry) => entry.id === selectedId) ?? null;

  return (
    <div className="main">
      <header className="toolbar">
        <input
          type="search"
          placeholder="Search entries"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search entries"
        />
        <button type="button" className="primary" onClick={onNew}>
          New entry
        </button>
        <button type="button" onClick={onSettings}>
          Settings
        </button>
        <button type="button" onClick={onLock}>
          Lock
        </button>
      </header>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      <div className="panes">
        <ul className="entry-list" aria-label="Entries">
          {entries.length === 0 && (
            <li className="hint empty">{query ? "No matches." : "No entries yet."}</li>
          )}
          {entries.map((entry) => (
            <li key={entry.id}>
              <button
                type="button"
                className={entry.id === selectedId ? "entry selected" : "entry"}
                onClick={() => setSelectedId(entry.id)}
              >
                <strong>{entry.title}</strong>
                <span>{entry.username}</span>
              </button>
            </li>
          ))}
        </ul>

        {selected ? (
          <EntryDetail
            key={selected.id}
            entry={selected}
            onEdit={() => onEdit(selected)}
            onDeleted={() => {
              setSelectedId(null);
              setVersion((v) => v + 1);
            }}
          />
        ) : (
          <p className="hint detail-empty">Select an entry to see its details.</p>
        )}
      </div>
    </div>
  );
}
