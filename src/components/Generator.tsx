import { useState } from "react";
import { api, errorText } from "../api";

interface Props {
  /** Receives the generated text so the form can put it in the password field. */
  onGenerated: (text: string) => void;
}

/**
 * Options for the password generator. Generated text is handed straight to
 * the form (it is being typed into one anyway); only its strength is kept here.
 */
export function Generator({ onGenerated }: Props) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [length, setLength] = useState(20);
  const [lowercase, setLowercase] = useState(true);
  const [uppercase, setUppercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [words, setWords] = useState(6);
  const [bits, setBits] = useState<number | null>(null);
  const [error, setError] = useState("");

  async function generate() {
    setError("");
    try {
      const result =
        mode === "password"
          ? await api.generatePassword({ length, lowercase, uppercase, digits, symbols })
          : await api.generatePassphrase({ words, separator: null });
      setBits(result.entropy_bits);
      onGenerated(result.text);
    } catch (e) {
      setError(errorText(e));
    }
  }

  return (
    <fieldset className="generator">
      <legend>Generate</legend>
      <div className="row">
        <label className="check">
          <input type="radio" checked={mode === "password"} onChange={() => setMode("password")} />
          Password
        </label>
        <label className="check">
          <input
            type="radio"
            checked={mode === "passphrase"}
            onChange={() => setMode("passphrase")}
          />
          Passphrase
        </label>
      </div>

      {mode === "password" ? (
        <>
          <label>
            Length: {length}
            <input
              type="range"
              min={8}
              max={128}
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
            />
          </label>
          <div className="row">
            <label className="check">
              <input type="checkbox" checked={lowercase} onChange={(e) => setLowercase(e.target.checked)} />
              a-z
            </label>
            <label className="check">
              <input type="checkbox" checked={uppercase} onChange={(e) => setUppercase(e.target.checked)} />
              A-Z
            </label>
            <label className="check">
              <input type="checkbox" checked={digits} onChange={(e) => setDigits(e.target.checked)} />
              0-9
            </label>
            <label className="check">
              <input type="checkbox" checked={symbols} onChange={(e) => setSymbols(e.target.checked)} />
              !@#
            </label>
          </div>
        </>
      ) : (
        <label>
          Words: {words}
          <input
            type="range"
            min={3}
            max={20}
            value={words}
            onChange={(e) => setWords(Number(e.target.value))}
          />
        </label>
      )}

      <div className="row">
        <button type="button" onClick={generate}>
          Generate and use
        </button>
        {bits !== null && <span className="hint">about {Math.round(bits)} bits of entropy</span>}
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </fieldset>
  );
}
