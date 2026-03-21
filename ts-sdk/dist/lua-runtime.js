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
import { LuaFactory } from 'wasmoon';
import { createHash } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
/**
 * Minimal pure-Lua JSON encoder/decoder.
 *
 * We need this because wasmoon converts JS objects to Lua userdata,
 * and we need native Lua tables for ipairs/# to work correctly.
 * All data marshalling between JS and Lua goes through JSON strings.
 */
const LUA_JSON_LIB = `
local __json = {}

-- Decode JSON string to native Lua table
function __json.decode(str)
  if str == nil or str == "" then return nil end
  local pos = 1

  local function skip_ws()
    pos = str:match("^%s*()", pos)
  end

  local function peek()
    skip_ws()
    return str:sub(pos, pos)
  end

  local decode_value -- forward declaration

  local function decode_string()
    pos = pos + 1 -- skip opening quote
    local parts = {}
    while pos <= #str do
      local c = str:sub(pos, pos)
      if c == '"' then
        pos = pos + 1
        return table.concat(parts)
      elseif c == '\\\\' then
        pos = pos + 1
        local esc = str:sub(pos, pos)
        if esc == '"' or esc == '\\\\' or esc == '/' then
          parts[#parts + 1] = esc
        elseif esc == 'n' then parts[#parts + 1] = '\\n'
        elseif esc == 'r' then parts[#parts + 1] = '\\r'
        elseif esc == 't' then parts[#parts + 1] = '\\t'
        elseif esc == 'b' then parts[#parts + 1] = '\\b'
        elseif esc == 'f' then parts[#parts + 1] = '\\f'
        elseif esc == 'u' then
          local hex = str:sub(pos + 1, pos + 4)
          pos = pos + 4
          local code = tonumber(hex, 16)
          if code then
            if code < 128 then
              parts[#parts + 1] = string.char(code)
            else
              parts[#parts + 1] = '?' -- simplified; non-ASCII as ?
            end
          end
        end
        pos = pos + 1
      else
        parts[#parts + 1] = c
        pos = pos + 1
      end
    end
    error("unterminated string")
  end

  local function decode_number()
    local start = pos
    if str:sub(pos, pos) == '-' then pos = pos + 1 end
    while pos <= #str and str:sub(pos, pos):match('[0-9]') do pos = pos + 1 end
    if pos <= #str and str:sub(pos, pos) == '.' then
      pos = pos + 1
      while pos <= #str and str:sub(pos, pos):match('[0-9]') do pos = pos + 1 end
    end
    if pos <= #str and str:sub(pos, pos):match('[eE]') then
      pos = pos + 1
      if pos <= #str and str:sub(pos, pos):match('[+-]') then pos = pos + 1 end
      while pos <= #str and str:sub(pos, pos):match('[0-9]') do pos = pos + 1 end
    end
    return tonumber(str:sub(start, pos - 1))
  end

  local function decode_array()
    pos = pos + 1 -- skip [
    local arr = {}
    skip_ws()
    if str:sub(pos, pos) == ']' then
      pos = pos + 1
      return arr
    end
    while true do
      arr[#arr + 1] = decode_value()
      skip_ws()
      local c = str:sub(pos, pos)
      if c == ']' then
        pos = pos + 1
        return arr
      elseif c == ',' then
        pos = pos + 1
      else
        error("expected ',' or ']' at position " .. pos)
      end
    end
  end

  local function decode_object()
    pos = pos + 1 -- skip {
    local obj = {}
    skip_ws()
    if str:sub(pos, pos) == '}' then
      pos = pos + 1
      return obj
    end
    while true do
      skip_ws()
      local key = decode_string()
      skip_ws()
      if str:sub(pos, pos) ~= ':' then error("expected ':' at position " .. pos) end
      pos = pos + 1
      obj[key] = decode_value()
      skip_ws()
      local c = str:sub(pos, pos)
      if c == '}' then
        pos = pos + 1
        return obj
      elseif c == ',' then
        pos = pos + 1
      else
        error("expected ',' or '}' at position " .. pos)
      end
    end
  end

  function decode_value()
    skip_ws()
    local c = str:sub(pos, pos)
    if c == '"' then return decode_string()
    elseif c == '{' then return decode_object()
    elseif c == '[' then return decode_array()
    elseif c == 't' then pos = pos + 4; return true
    elseif c == 'f' then pos = pos + 5; return false
    elseif c == 'n' then pos = pos + 4; return nil
    elseif c == '-' or c:match('[0-9]') then return decode_number()
    else error("unexpected character '" .. c .. "' at position " .. pos)
    end
  end

  return decode_value()
end

-- Encode Lua value to JSON string
function __json.encode(val)
  if val == nil then return "null" end
  local t = type(val)
  if t == "boolean" then return val and "true" or "false" end
  if t == "number" then
    if val ~= val then return "null" end -- NaN
    if val == math.huge or val == -math.huge then return "null" end
    if val == math.floor(val) and math.abs(val) < 2^53 then
      return string.format("%.0f", val)
    end
    return tostring(val)
  end
  if t == "string" then
    val = val:gsub('\\\\', '\\\\\\\\'):gsub('"', '\\\\"'):gsub('\\n', '\\\\n'):gsub('\\r', '\\\\r'):gsub('\\t', '\\\\t')
    return '"' .. val .. '"'
  end
  if t == "table" then
    -- Check if it's an array (sequential integer keys starting from 1)
    local n = #val
    local is_array = true
    if n == 0 then
      -- Check if table has any keys
      if next(val) ~= nil then
        is_array = false
      end
    else
      for k in pairs(val) do
        if type(k) ~= "number" or k < 1 or k > n or k ~= math.floor(k) then
          is_array = false
          break
        end
      end
    end

    if is_array then
      local parts = {}
      for i = 1, n do
        parts[i] = __json.encode(val[i])
      end
      return "[" .. table.concat(parts, ",") .. "]"
    else
      local parts = {}
      for k, v in pairs(val) do
        parts[#parts + 1] = __json.encode(tostring(k)) .. ":" .. __json.encode(v)
      end
      return "{" .. table.concat(parts, ",") .. "}"
    end
  end
  return "null"
end
`;
/**
 * Lua setup script that initializes _RPC table and args global.
 */
const LUA_SETUP_SCRIPT = `
-- Decode args from JSON to get native Lua tables
args = __json.decode(__args_json)

-- Set up _RPC table with metatable for dynamic dispatch
_RPC = setmetatable({}, {
  __index = function(t, method)
    local fn = function(...)
      local call_args = {...}
      local args_json = __json.encode(call_args)
      local resp_json = __call_rpc(method, args_json)
      local resp = __json.decode(resp_json)
      if resp.error then
        return nil
      end
      return resp.result
    end
    rawset(t, method, fn)
    return fn
  end
})
`;
/**
 * Pre-loaded Lua scripts stored by SHA-256 hash.
 * Used by lua_evalsaved / sandshrew_evalsaved.
 */
const scriptStore = new Map();
/** Compute SHA-256 hex digest of a string. */
function sha256(content) {
    return createHash('sha256').update(content, 'utf8').digest('hex');
}
/**
 * Load all known Lua scripts from a directory into the script store.
 * Typically called with ~/alkanes-rs/lua/.
 */
export function preloadLuaScripts(luaDir) {
    const scripts = [
        'balances.lua',
        'spendable_utxos.lua',
        'multicall.lua',
        'batch_utxo_balances.lua',
        'address_utxos_with_txs.lua',
    ];
    for (const name of scripts) {
        const filePath = resolve(luaDir, name);
        if (existsSync(filePath)) {
            const content = readFileSync(filePath, 'utf8');
            const hash = sha256(content);
            scriptStore.set(hash, content);
        }
    }
}
/**
 * Save a script and return its hash (sandshrew_savescript).
 */
export function saveScript(content) {
    const hash = sha256(content);
    scriptStore.set(hash, content);
    return hash;
}
/**
 * Look up a saved script by hash.
 */
export function getScript(hash) {
    return scriptStore.get(hash);
}
/**
 * LuaRuntime — manages a wasmoon Lua engine with _RPC table registered.
 *
 * Usage:
 *   const runtime = await LuaRuntime.create(handleRpc);
 *   const result = runtime.executeScript(scriptContent, args);
 */
export class LuaRuntime {
    factory;
    rpcHandler;
    constructor(factory, rpcHandler) {
        this.factory = factory;
        this.rpcHandler = rpcHandler;
    }
    static async create(rpcHandler) {
        const factory = new LuaFactory();
        return new LuaRuntime(factory, rpcHandler);
    }
    /**
     * Execute a Lua script with arguments.
     *
     * The script receives `args` as a global Lua table, and has access to
     * `_RPC` table where each method routes back to the devnet RPC handler.
     *
     * Returns the script's return value (serialized as JSON-compatible JS value).
     */
    async executeScript(scriptContent, args) {
        const startTime = Date.now();
        let callCount = 0;
        let engine = null;
        try {
            engine = await this.factory.createEngine({
                openStandardLibs: true,
                // injectObjects: false — we handle all data marshalling through JSON
                // strings because wasmoon converts JS objects to Lua userdata which
                // doesn't support ipairs/# properly.
            });
            // Serialize args as JSON string
            engine.global.set('__args_json', JSON.stringify(args));
            // Register a JS function that dispatches RPC calls.
            // Takes method + args as JSON string, returns response as JSON string.
            const rpcHandler = this.rpcHandler;
            engine.global.set('__call_rpc', (method, argsJson) => {
                callCount++;
                const fnArgs = JSON.parse(argsJson);
                const requestJson = JSON.stringify({
                    jsonrpc: '2.0',
                    method,
                    params: fnArgs,
                    id: callCount,
                });
                const responseJson = rpcHandler(requestJson);
                return responseJson;
            });
            // Load the pure-Lua JSON library and set up _RPC + args.
            // All data goes through JSON strings to get native Lua tables.
            const setupScript = LUA_JSON_LIB + `\n` + LUA_SETUP_SCRIPT;
            await engine.doString(setupScript);
            // Execute the script. We wrap in a function so `return` works at top level.
            const wrappedScript = `return (function()\n${scriptContent}\nend)()`;
            const result = await engine.doString(wrappedScript);
            return {
                calls: callCount,
                returns: luaToJs(result),
                runtime: Date.now() - startTime,
            };
        }
        catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            return {
                calls: callCount,
                returns: null,
                runtime: Date.now() - startTime,
                error: message,
            };
        }
        finally {
            if (engine) {
                engine.global.close();
            }
        }
    }
    /**
     * Execute a saved script by hash.
     */
    async executeSaved(hash, args) {
        const content = scriptStore.get(hash);
        if (!content) {
            return {
                calls: 0,
                returns: null,
                runtime: 0,
                error: `Script not found for hash: ${hash}`,
            };
        }
        return this.executeScript(content, args);
    }
}
/**
 * Convert Lua return values to plain JS objects.
 *
 * wasmoon returns Lua tables as JS Maps/objects, but we need
 * plain objects/arrays for JSON serialization.
 */
function luaToJs(value) {
    if (value === null || value === undefined)
        return null;
    if (typeof value === 'number' || typeof value === 'string' || typeof value === 'boolean') {
        return value;
    }
    if (value instanceof Map) {
        const keys = Array.from(value.keys());
        // Empty map → empty array (Lua empty tables {} are usually intended as arrays)
        if (keys.length === 0) {
            return [];
        }
        // Determine if this is an array-like table (sequential integer keys starting from 1)
        const isArray = keys.every((k, i) => k === i + 1);
        if (isArray) {
            return keys.map(k => luaToJs(value.get(k)));
        }
        // Object-like table
        const obj = {};
        for (const [k, v] of value.entries()) {
            obj[String(k)] = luaToJs(v);
        }
        return obj;
    }
    if (Array.isArray(value)) {
        return value.map(luaToJs);
    }
    if (typeof value === 'object') {
        const entries = Object.entries(value);
        // Empty plain object → empty array (Lua empty tables are usually array containers)
        if (entries.length === 0) {
            return [];
        }
        // Check if all keys are sequential integers (1-based, from Lua table.insert)
        const isArray = entries.every(([k], i) => String(i + 1) === k);
        if (isArray) {
            return entries.map(([, v]) => luaToJs(v));
        }
        const obj = {};
        for (const [k, v] of entries) {
            obj[k] = luaToJs(v);
        }
        return obj;
    }
    return value;
}
//# sourceMappingURL=lua-runtime.js.map