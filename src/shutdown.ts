/**
 * Interrupt handling for the two executables.
 *
 * The first SIGINT or SIGTERM aborts the work in progress through its
 * AbortSignal: git is killed, sockets are destroyed, the walks stop, and a
 * partial clone is removed on the normal unwinding path. A second signal
 * means the user will not wait, so whatever clone directories remain are
 * removed synchronously and the process exits at once.
 */
import { removeActiveClonesSync } from "./clone";

/** The conventional exit status for a process ended by `signal` (128 + its number). */
export function signalExitCode(signal: NodeJS.Signals): number {
  return signal === "SIGINT" ? 130 : 143;
}

/**
 * Route SIGINT and SIGTERM to `controller` until the returned function is
 * called. `onAbort` runs once, with the signal, when the first one arrives.
 */
export function abortOnSignals(controller: AbortController, onAbort?: (signal: NodeJS.Signals) => void): () => void {
  const handler = (signal: NodeJS.Signals): void => {
    if (controller.signal.aborted) {
      removeActiveClonesSync();
      process.exit(signalExitCode(signal));
    }
    onAbort?.(signal);
    controller.abort(new Error(`interrupted by ${signal}`));
  };
  process.on("SIGINT", handler);
  process.on("SIGTERM", handler);
  return () => {
    process.off("SIGINT", handler);
    process.off("SIGTERM", handler);
  };
}
