/* Tiny shared store: the catalog is fetched once and reused by every module. */

import { api } from "./utils.js";

const state = { meta: null, attacks: [], readmes: [], ready: false };
const listeners = new Set();

export function catalogData() {
  return state;
}

export async function loadCatalog({ force = false } = {}) {
  if (state.ready && !force) return state;
  const [meta, summary] = await Promise.all([api("/api/meta"), api("/api/summary")]);
  state.meta = meta;
  state.attacks = summary.items;
  state.readmes = summary.readme_items;
  state.ready = true;
  for (const listener of listeners) listener(state);
  return state;
}

export function onCatalog(listener) {
  if (state.ready) listener(state);
  else listeners.add(listener);
}
