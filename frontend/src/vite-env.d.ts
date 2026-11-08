/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** `"true"` serves every API call from the in-memory mock client (`bun run dev:mock`). */
  readonly VITE_USE_MOCKS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
