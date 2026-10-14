import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

function App() {
  const [coreVersion, setCoreVersion] = useState("");

  useEffect(() => {
    invoke<string>("core_version").then(setCoreVersion);
  }, []);

  return (
    <main className="container">
      <h1>Password Locker</h1>
      <p className="muted">core {coreVersion}</p>
    </main>
  );
}

export default App;
