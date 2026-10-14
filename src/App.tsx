import { useCallback, useEffect, useState } from "react";
import { api, errorText, onVaultLocked, type EntrySummary } from "./api";
import { EntryForm } from "./components/EntryForm";
import { Main } from "./components/Main";
import { RestoreBackup } from "./components/RestoreBackup";
import { RecoveryCode } from "./components/RecoveryCode";
import { Settings } from "./components/Settings";
import { Setup } from "./components/Setup";
import { Unlock } from "./components/Unlock";
import "./App.css";

/** Which screen is showing. Secrets live inside the screen's own state. */
type Screen =
  | { name: "loading" }
  | { name: "fatal"; message: string }
  | { name: "setup" }
  | { name: "setup-code"; code: string }
  | { name: "unlock" }
  | { name: "main" }
  | { name: "form"; entry: EntrySummary | null }
  | { name: "settings" }
  | { name: "restore"; replacing: boolean }
  | { name: "rotation-code"; code: string };

/** At most one keep-alive call per this many milliseconds. */
const KEEP_ALIVE_EVERY = 30_000;

function App() {
  const [screen, setScreen] = useState<Screen>({ name: "loading" });
  const [vaultPath, setVaultPath] = useState("");

  const unlocked =
    ["main", "form", "settings", "rotation-code"].includes(screen.name) ||
    (screen.name === "restore" && screen.replacing);

  // Decide the first screen from what Rust says about the vault.
  useEffect(() => {
    api
      .status()
      .then(async (status) => {
        setVaultPath(status.vault_path);
        if (!status.vault_exists) {
          // A setup left half-done (for example by a reload) cannot be
          // resumed, because the recovery code is not kept anywhere.
          if (status.setup_pending) await api.cancelSetup();
          setScreen({ name: "setup" });
        } else {
          setScreen(status.unlocked ? { name: "main" } : { name: "unlock" });
        }
      })
      .catch((e) => setScreen({ name: "fatal", message: errorText(e) }));
  }, []);

  // Rust locks the vault on idle or when Windows locks. Replacing the screen
  // unmounts every component, which drops all entry data and revealed secrets.
  useEffect(() => {
    const pending = onVaultLocked(() => setScreen({ name: "unlock" }));
    return () => {
      void pending.then((unlisten) => unlisten());
    };
  }, []);

  // While the user is active, tell Rust so the idle timer restarts.
  useEffect(() => {
    if (!unlocked) return;
    let last = Date.now();
    const onActivity = () => {
      if (Date.now() - last < KEEP_ALIVE_EVERY) return;
      last = Date.now();
      api.keepAlive().catch(() => {});
    };
    window.addEventListener("keydown", onActivity);
    window.addEventListener("pointerdown", onActivity);
    return () => {
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("pointerdown", onActivity);
    };
  }, [unlocked]);

  const lock = useCallback(async () => {
    try {
      await api.lock();
    } finally {
      setScreen({ name: "unlock" });
    }
  }, []);

  switch (screen.name) {
    case "loading":
      return <main className="card"><p className="hint">Loading...</p></main>;

    case "fatal":
      return (
        <main className="card">
          <h1>Password Locker</h1>
          <p className="error" role="alert">{screen.message}</p>
        </main>
      );

    case "setup":
      return (
        <Setup
          onCode={(code) => setScreen({ name: "setup-code", code })}
          onRestore={() => setScreen({ name: "restore", replacing: false })}
        />
      );

    case "restore":
      return (
        <RestoreBackup
          replacing={screen.replacing}
          onRestored={() => setScreen({ name: "main" })}
          onCancel={() => setScreen(screen.replacing ? { name: "settings" } : { name: "setup" })}
        />
      );

    case "setup-code":
      return (
        <RecoveryCode
          title="Save your recovery code"
          code={screen.code}
          onConfirm={async (typed) => {
            await api.finishSetup(typed);
            setScreen({ name: "main" });
          }}
          onCancel={() => {
            void api.cancelSetup();
            setScreen({ name: "setup" });
          }}
        />
      );

    case "unlock":
      return <Unlock onUnlocked={() => setScreen({ name: "main" })} />;

    case "main":
      return (
        <Main
          onNew={() => setScreen({ name: "form", entry: null })}
          onEdit={(entry) => setScreen({ name: "form", entry })}
          onSettings={() => setScreen({ name: "settings" })}
          onLock={lock}
        />
      );

    case "form":
      return <EntryForm entry={screen.entry} onDone={() => setScreen({ name: "main" })} />;

    case "settings":
      return (
        <Settings
          vaultPath={vaultPath}
          onRotation={(code) => setScreen({ name: "rotation-code", code })}
          onRestore={() => setScreen({ name: "restore", replacing: true })}
          onBack={() => setScreen({ name: "main" })}
          onLock={lock}
        />
      );

    case "rotation-code":
      return (
        <RecoveryCode
          title="Your new recovery code"
          code={screen.code}
          onConfirm={async (typed) => {
            await api.finishRecoveryRotation(typed);
            setScreen({ name: "settings" });
          }}
          onCancel={() => {
            void api.cancelRecoveryRotation();
            setScreen({ name: "settings" });
          }}
        />
      );
  }
}

export default App;
