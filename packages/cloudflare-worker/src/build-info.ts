/**
 * Populated at deploy time via esbuild `--define` (see scripts/deploy.mjs),
 * not committed source - `wrangler deploy` computes these fresh from `git`
 * on every deploy so /version always reflects the commit actually uploaded.
 *
 * `typeof X !== 'undefined'` is the safe way to read an esbuild `define`
 * identifier that might not have been provided (e.g. `wrangler dev` without
 * running through scripts/deploy.mjs) - referencing the bare identifier
 * directly would throw a ReferenceError in that case, since esbuild only
 * replaces the token where it's given a value; it doesn't declare a global.
 */
declare const __GIT_COMMIT__: string;
declare const __BUILD_TIME__: string;

export const GIT_COMMIT = typeof __GIT_COMMIT__ !== 'undefined' ? __GIT_COMMIT__ : 'unknown';
export const BUILD_TIME = typeof __BUILD_TIME__ !== 'undefined' ? __BUILD_TIME__ : 'unknown';
