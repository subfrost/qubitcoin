/**
 * Lua Runtime for DevnetTestHarness — executes Lua scripts via wasmoon.
 *
 * Provides a real Lua 5.4 VM (compiled to WASM) that can execute the
 * alkanes Lua scripts (balances, spendable_utxos, multicall, etc.)
 * with full _RPC table support. Each _RPC.method() call routes back
 * into the devnet's handleRpc() for actual execution.
 *
 * This replaces the hardcoded Rust shims in alkanes-rpc-core/dispatch.rs
 * for the Node.js devnet environment.
 */
/** Callback type for routing _RPC calls back to the devnet. */
export type RpcHandler = (requestJson: string) => string;
/**
 * Load all known Lua scripts from a directory into the script store.
 * Typically called with ~/alkanes-rs/lua/.
 */
export declare function preloadLuaScripts(luaDir: string): void;
/**
 * Save a script and return its hash (sandshrew_savescript).
 */
export declare function saveScript(content: string): string;
/**
 * Look up a saved script by hash.
 */
export declare function getScript(hash: string): string | undefined;
/**
 * LuaRuntime — manages a wasmoon Lua engine with _RPC table registered.
 *
 * Usage:
 *   const runtime = await LuaRuntime.create(handleRpc);
 *   const result = runtime.executeScript(scriptContent, args);
 */
export declare class LuaRuntime {
    private factory;
    private rpcHandler;
    private constructor();
    static create(rpcHandler: RpcHandler): Promise<LuaRuntime>;
    /**
     * Execute a Lua script with arguments.
     *
     * The script receives `args` as a global Lua table, and has access to
     * `_RPC` table where each method routes back to the devnet RPC handler.
     *
     * Returns the script's return value (serialized as JSON-compatible JS value).
     */
    executeScript(scriptContent: string, args: unknown[]): Promise<{
        calls: number;
        returns: unknown;
        runtime: number;
        error?: string;
    }>;
    /**
     * Execute a saved script by hash.
     */
    executeSaved(hash: string, args: unknown[]): Promise<{
        calls: number;
        returns: unknown;
        runtime: number;
        error?: string;
    }>;
}
//# sourceMappingURL=lua-runtime.d.ts.map