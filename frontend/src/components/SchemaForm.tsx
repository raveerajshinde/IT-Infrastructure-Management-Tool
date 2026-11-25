// Renders a form from the backend's Pydantic JSON Schema. The server re-validates everything;
// this only provides good UX (types, enums, limits, patterns).
import { useState } from "react";
import type { JsonSchema } from "../lib/types";
import { label as humanize } from "../lib/format";

function resolve(s: JsonSchema, root: JsonSchema): JsonSchema {
  if (s.$ref) {
    const name = s.$ref.split("/").pop()!;
    return root.$defs?.[name] || s;
  }
  if (s.anyOf) {
    const nonNull = s.anyOf.filter((x) => x.type !== "null");
    if (nonNull.length === 1) return { ...nonNull[0], title: s.title, description: s.description, default: s.default };
  }
  return s;
}

/** Free-text editors keep their own text so separators (",", "=") can be typed; parsed values are pushed up. */
function ListInput({ id, value, onChange }: { id: string; value: unknown; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(Array.isArray(value) ? value.join(", ") : "");
  return <input id={id} className="input" placeholder="comma-separated" value={text}
    onChange={(e) => { setText(e.target.value); onChange(e.target.value.split(",").map((x) => x.trim()).filter(Boolean)); }} />;
}

function MapInput({ id, value, onChange }: { id: string; value: unknown; onChange: (v: Record<string, string>) => void }) {
  const [text, setText] = useState(Object.entries((value || {}) as Record<string, unknown>).map(([a, b]) => `${a}=${b}`).join("\n"));
  return <textarea id={id} className="input font-mono" rows={3} placeholder="key=value (one per line)" value={text}
    onChange={(e) => { setText(e.target.value); onChange(Object.fromEntries(e.target.value.split("\n").filter((l) => l.includes("="))
      .map((l) => [l.split("=")[0].trim(), l.slice(l.indexOf("=") + 1).trim()]))); }} />;
}

export function initialValues(schema: JsonSchema, base: Record<string, unknown> = {}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  Object.entries(schema.properties || {}).forEach(([k, raw]) => {
    const s = resolve(raw, schema);
    let b = base[k];
    if (b !== undefined && b !== null && s.type === "array" && !Array.isArray(b)) b = [b];  // a single row value pre-filling a list field
    if (b !== undefined && b !== null && s.type === "string" && typeof b !== "string") b = String(b);
    out[k] = b !== undefined ? b : s.default !== undefined ? s.default : s.type === "boolean" ? false : s.type === "array" ? [] : s.type === "object" ? {} : "";
  });
  return out;
}

export function cleanValues(schema: JsonSchema, values: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const required = new Set(schema.required || []);
  Object.entries(schema.properties || {}).forEach(([k, raw]) => {
    const s = resolve(raw, schema);
    let v = values[k];
    if ((s.type === "integer" || s.type === "number") && v !== "" && v !== null && v !== undefined) v = Number(v);
    const nullable = !!raw.anyOf?.some((x) => x.type === "null");
    if ((v === "" || v === null) && !required.has(k)) { if (nullable) return; if (s.default !== undefined) { out[k] = s.default; return; } return; }
    out[k] = v;
  });
  return out;
}

export function SchemaForm({ schema, values, onChange, errors = {} }: {
  schema: JsonSchema; values: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void; errors?: Record<string, string>;
}) {
  const props = Object.entries(schema.properties || {});
  if (!props.length) return <p className="text-sm text-slate-500">This operation takes no parameters.</p>;
  const req = new Set(schema.required || []);
  const set = (k: string, v: unknown) => onChange({ ...values, [k]: v });
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      {props.map(([key, raw]) => {
        const s = resolve(raw, schema);
        const id = `f-${key}`;
        const title = humanize(raw.title || key);
        const hint = raw.description || s.description;
        const v = values[key];
        const err = errors[key];
        let input: JSX.Element;
        const nullableBool = raw.anyOf?.some((x) => x.type === "null") && s.type === "boolean";
        if (s.enum) {
          input = (
            <select id={id} className="input" value={String(v ?? "")} onChange={(e) => set(key, e.target.value)}>
              {!req.has(key) && <option value="">—</option>}
              {s.enum.map((o) => <option key={String(o)} value={String(o)}>{String(o)}</option>)}
            </select>
          );
        } else if (nullableBool) {
          input = (
            <select id={id} className="input" value={v === true ? "true" : v === false ? "false" : ""} onChange={(e) => set(key, e.target.value === "" ? "" : e.target.value === "true")}>
              <option value="">(unchanged)</option><option value="true">Yes</option><option value="false">No</option>
            </select>
          );
        } else if (s.type === "boolean") {
          input = (
            <label className="flex h-[38px] items-center gap-2 text-sm">
              <input id={id} type="checkbox" className="h-4 w-4 rounded border-slate-300" checked={!!v} onChange={(e) => set(key, e.target.checked)} /> {v ? "Yes" : "No"}
            </label>
          );
        } else if (s.type === "integer" || s.type === "number") {
          input = <input id={id} type="number" className="input" value={v === undefined || v === null ? "" : String(v)} min={s.minimum} max={s.maximum}
            onChange={(e) => set(key, e.target.value)} required={req.has(key)} />;
        } else if (s.type === "array") {
          input = <ListInput id={id} value={v} onChange={(x) => set(key, x)} />;
        } else if (s.type === "object") {
          input = <MapInput id={id} value={v} onChange={(x) => set(key, x)} />;
        } else {
          const secret = s.format === "password" || s.writeOnly;
          input = <input id={id} className="input" type={secret ? "password" : "text"} autoComplete={secret ? "new-password" : "off"} value={String(v ?? "")}
            maxLength={s.maxLength} required={req.has(key)} onChange={(e) => set(key, e.target.value)} />;
        }
        return (
          <div key={key} className={s.type === "object" ? "sm:col-span-2" : ""}>
            <label className="label" htmlFor={id}>{title}{req.has(key) && <span className="text-red-500"> *</span>}</label>
            {input}
            {err ? <p className="mt-1 text-xs text-red-600">{err}</p> : hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
          </div>
        );
      })}
    </div>
  );
}
