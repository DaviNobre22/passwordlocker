// Typed wrappers around the Tauri commands in src-tauri/src/lib.rs. This is
// the only file that calls `invoke`, so it is the one place to check what
// crosses between the window and Rust.
//
// Argument names are camelCase here because Tauri converts them to the
// snake_case names of the Rust functions. Fields inside objects keep the
// snake_case names Rust uses.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface Status {
  vault_exists: boolean;
  unlocked: boolean;
  vault_path: string;
  setup_pending: boolean;
}

/** What a list shows. Deliberately has no password or notes. */
export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  tags: string[];
  updated_at: number;
}

/** `password` / `notes` of null mean "keep the stored value" (edit) or empty (new). */
export interface EntryDraft {
  title: string;
  username: string;
  password: string | null;
  url: string;
  notes: string | null;
  tags: string[];
}

export interface PastPassword {
  password: string;
  replaced_at: number;
}

export interface Generated {
  text: string;
  entropy_bits: number;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string | null;
}

export const api = {
  status: () => invoke<Status>("status"),

  beginSetup: (password: string) => invoke<string>("begin_setup", { password }),
  finishSetup: (typedCode: string) => invoke<void>("finish_setup", { typedCode }),
  cancelSetup: () => invoke<void>("cancel_setup"),

  unlock: (password: string) => invoke<void>("unlock", { password }),
  unlockWithRecovery: (password: string, code: string) =>
    invoke<void>("unlock_with_recovery", { password, code }),
  lock: () => invoke<void>("lock"),
  keepAlive: () => invoke<void>("keep_alive"),

  listEntries: (query: string) => invoke<EntrySummary[]>("list_entries", { query }),
  addEntry: (draft: EntryDraft) => invoke<string>("add_entry", { draft }),
  updateEntry: (id: string, draft: EntryDraft) => invoke<void>("update_entry", { id, draft }),
  deleteEntry: (id: string) => invoke<void>("delete_entry", { id }),

  revealPassword: (id: string) => invoke<string>("reveal_password", { id }),
  revealNotes: (id: string) => invoke<string>("reveal_notes", { id }),
  revealPasswordHistory: (id: string) =>
    invoke<PastPassword[]>("reveal_password_history", { id }),
  copyPassword: (id: string) => invoke<void>("copy_password", { id }),
  copyUsername: (id: string) => invoke<void>("copy_username", { id }),

  generatePassword: (options: PasswordOptions) =>
    invoke<Generated>("generate_password", { options }),
  generatePassphrase: (options: PassphraseOptions) =>
    invoke<Generated>("generate_passphrase", { options }),

  changeMasterPassword: (current: string, newPassword: string) =>
    invoke<void>("change_master_password", { current, newPassword }),
  beginRecoveryRotation: () => invoke<string>("begin_recovery_rotation"),
  finishRecoveryRotation: (typedCode: string) =>
    invoke<void>("finish_recovery_rotation", { typedCode }),
  cancelRecoveryRotation: () => invoke<void>("cancel_recovery_rotation"),
};

/** Runs `handler` when Rust locks the vault (idle timeout or Windows lock). */
export function onVaultLocked(handler: () => void): Promise<UnlistenFn> {
  return listen("vault-locked", handler);
}

/** Errors from commands arrive as plain strings. */
export function errorText(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}
