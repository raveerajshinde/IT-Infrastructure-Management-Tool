import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useMemo, useState } from "react";
import { ApiError, api } from "../lib/api";
import { DEVICE_TYPE_LABEL } from "../lib/format";
import type { Credential, Device, Meta, Site } from "../lib/types";
import { Button, Callout, ErrorBox, Field, Modal, useToast } from "./ui";

type Form = {
  hostname: string; ip_address: string; device_type: string; driver: string; vendor: string; model: string; os_name: string; os_version: string;
  firmware: string; serial_number: string; owner: string; department: string; environment: string; site_id: string; credential_id: string;
  snmp_credential_id: string; port: string; notes: string; tags: string; is_simulated: boolean;
  opt_verify_tls: boolean; monitoring_enabled: boolean;
};

function toForm(d?: Device): Form {
  const o = (d?.options || {}) as Record<string, unknown>;
  return {
    hostname: d?.hostname || "", ip_address: d?.ip_address || "", device_type: d?.device_type || "linux_server", driver: d?.driver || "linux",
    vendor: d?.vendor || "", model: d?.model || "", os_name: d?.os_name || "", os_version: d?.os_version || "", firmware: d?.firmware || "",
    serial_number: d?.serial_number || "", owner: d?.owner || "", department: d?.department || "", environment: d?.environment || "production",
    site_id: d?.site_id ? String(d.site_id) : "", credential_id: d?.credential_id ? String(d.credential_id) : "",
    snmp_credential_id: d?.snmp_credential_id ? String(d.snmp_credential_id) : "", port: d?.port ? String(d.port) : "", notes: d?.notes || "",
    tags: (d?.tags || []).join(", "), is_simulated: d?.is_simulated || false,
    opt_verify_tls: o.verify_tls !== false, monitoring_enabled: d?.monitoring_enabled !== false,
  };
}

export function DeviceForm({ device, onClose, onSaved }: { device?: Device; onClose: () => void; onSaved?: (d: Device) => void }) {
  const [f, setF] = useState<Form>(() => toForm(device));
  const [err, setErr] = useState<unknown>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: () => api<Meta>("/api/meta") });
  const { data: sites } = useQuery({ queryKey: ["sites"], queryFn: () => api<Site[]>("/api/sites") });
  const { data: creds } = useQuery({ queryKey: ["credentials"], queryFn: () => api<Credential[]>("/api/credentials").catch(() => [] as Credential[]) });
  const drv = meta?.drivers.find((d) => d.name === f.driver);
  const drivers = useMemo(() => (meta?.drivers || []).filter((d) => f.is_simulated || !d.device_types.length || d.device_types.includes(f.device_type) || f.device_type === "other"), [meta, f.device_type, f.is_simulated]);
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((x) => ({ ...x, [k]: v }));
  const errs: Record<string, string> = {};
  if (err instanceof ApiError) err.fieldErrors.forEach((e) => (errs[e.field] = e.message));

  const save = useMutation({
    mutationFn: () => {
      const options: Record<string, unknown> = { verify_tls: f.opt_verify_tls };
      const body = {
        hostname: f.hostname, ip_address: f.ip_address, device_type: f.device_type, driver: f.driver, vendor: f.vendor, model: f.model,
        os_name: f.os_name, os_version: f.os_version, firmware: f.firmware, serial_number: f.serial_number, owner: f.owner, department: f.department,
        environment: f.environment, site_id: f.site_id ? Number(f.site_id) : null, credential_id: f.credential_id ? Number(f.credential_id) : null,
        snmp_credential_id: f.snmp_credential_id ? Number(f.snmp_credential_id) : null, port: f.port ? Number(f.port) : null, notes: f.notes,
        tags: f.tags.split(",").map((t) => t.trim()).filter(Boolean), is_simulated: f.is_simulated, options,
        monitoring_enabled: f.monitoring_enabled, groups: device?.groups,
      };
      return device ? api<Device>(`/api/devices/${device.id}`, { method: "PUT", body }) : api<Device>("/api/devices", { body });
    },
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ["devices"] }); qc.invalidateQueries({ queryKey: ["device", d.id] });
      toast({ tone: "success", title: device ? "Device updated" : "Device registered", body: device ? undefined : "Run a connectivity test to verify access." });
      onSaved?.(d); onClose();
    },
    onError: (e) => setErr(e),
  });
  const submit = (e: FormEvent) => { e.preventDefault(); setErr(null); save.mutate(); };
  const usable = (creds || []).filter((c) => c.kind !== "snmpv3" && (!drv || f.is_simulated || drv.credential_kinds.includes(c.kind)));
  const snmp = (creds || []).filter((c) => c.kind === "snmpv3");
  const T = (k: keyof Form, labelText: string, props: Record<string, unknown> = {}) => (
    <Field label={labelText} htmlFor={`d-${k}`} error={errs[k as string]} required={!!props.required}>
      <input id={`d-${k}`} className="input" value={f[k] as string} onChange={(e) => set(k, e.target.value as never)} {...props} />
    </Field>
  );

  return (
    <Modal open onClose={onClose} size="lg" title={device ? `Edit ${device.hostname}` : "Register device"}
      footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="devform" type="submit" loading={save.isPending}>{device ? "Save changes" : "Register device"}</Button></>}>
      <form id="devform" onSubmit={submit} className="space-y-4">
        <ErrorBox error={err} title="Could not save device" />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {T("hostname", "Hostname", { required: true, placeholder: "srv-app01" })}
          {T("ip_address", "IP address / DNS name", { required: true, placeholder: "10.0.10.21" })}
          <Field label="Device type" htmlFor="d-type" required>
            <select id="d-type" className="input" value={f.device_type} onChange={(e) => set("device_type", e.target.value)}>
              {(meta?.device_types || []).map((t) => <option key={t} value={t}>{DEVICE_TYPE_LABEL[t] || t}</option>)}
            </select>
          </Field>
          <Field label="Integration driver" htmlFor="d-drv" required hint={drv?.notes}>
            <select id="d-drv" className="input" value={f.driver} onChange={(e) => set("driver", e.target.value)}>
              {drivers.map((d) => <option key={d.name} value={d.name}>{d.label}</option>)}
            </select>
          </Field>
          <Field label="Environment" htmlFor="d-env">
            <select id="d-env" className="input" value={f.environment} onChange={(e) => set("environment", e.target.value)}>
              {(meta?.environments || []).map((t) => <option key={t}>{t}</option>)}
            </select>
          </Field>
          <Field label="Site" htmlFor="d-site">
            <select id="d-site" className="input" value={f.site_id} onChange={(e) => set("site_id", e.target.value)}>
              <option value="">—</option>{(sites || []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </Field>
          <Field label="Management credential" htmlFor="d-cred" hint={drv ? `Accepted kinds: ${drv.credential_kinds.join(", ")}` : undefined}>
            <select id="d-cred" className="input" value={f.credential_id} onChange={(e) => set("credential_id", e.target.value)}>
              <option value="">— none —</option>{usable.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.kind}{c.username ? `, ${c.username}` : ""})</option>)}
            </select>
          </Field>
          <Field label="SNMPv3 credential (monitoring)" htmlFor="d-snmp">
            <select id="d-snmp" className="input" value={f.snmp_credential_id} onChange={(e) => set("snmp_credential_id", e.target.value)}>
              <option value="">— none —</option>{snmp.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
          </Field>
          {T("port", `Port ${drv?.default_port ? `(default ${drv.default_port})` : ""}`, { type: "number", min: 1, max: 65535 })}
          {T("tags", "Tags (comma-separated)")}
        </div>

        {drv && (
          <div className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">{drv.label} — connection</p>
            <p className="mb-2 text-xs text-slate-500">Transport: {drv.transport}. Authentication options (WinRM authentication, sudo, SSH host-key policy, SNMPv3 protocols) are set on the credential.</p>
            {f.driver === "windows" && (
              <div className="mb-3">
                <p className="label">WinRM protocol</p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2" role="radiogroup" aria-label="WinRM protocol">
                  {([["5986", "HTTPS (port 5986)", "Needs a certificate on the server's WinRM HTTPS listener."],
                     ["5985", "HTTP (port 5985)", "Default WinRM listener, no certificate needed. Traffic is still encrypted by Negotiate/Kerberos/NTLM."]] as const).map(([port, title, hint]) => {
                    const on = port === "5985" ? f.port === "5985" : f.port !== "5985";
                    return (
                      <button key={port} type="button" role="radio" aria-checked={on} onClick={() => set("port", port)}
                        className={`rounded-md border p-2.5 text-left text-sm ${on ? "border-brand-500 bg-brand-50 ring-1 ring-brand-500 dark:bg-brand-900/30" : "border-slate-200 hover:border-slate-300 dark:border-slate-700"}`}>
                        <span className="font-medium">{title}</span><span className="mt-0.5 block text-xs text-slate-500">{hint}</span>
                      </button>
                    );
                  })}
                </div>
                {f.port === "5985" && <p className="mt-1.5 text-xs text-slate-500">Use a credential with Negotiate, NTLM or Kerberos authentication — Basic is refused over HTTP because it would expose the password. Certificate verification does not apply over HTTP.</p>}
              </div>
            )}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.opt_verify_tls} onChange={(e) => set("opt_verify_tls", e.target.checked)} /> Verify TLS certificate (HTTPS/WinRM/API drivers)</label>
              {["firewall", "hypervisor"].includes(f.device_type) && f.opt_verify_tls && <p className="mt-1 text-xs text-slate-500">Firewalls and hypervisors often ship with a self-signed certificate. If the connectivity test reports CERTIFICATE_VERIFY_FAILED, untick this (or install the device's CA on the InfraPilot host).</p>}
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.monitoring_enabled} onChange={(e) => set("monitoring_enabled", e.target.checked)} /> Monitor this device (availability and health polling)</label>
            </div>
            {!f.opt_verify_tls && !(f.driver === "windows" && f.port === "5985") && <div className="mt-2"><Callout tone="warning">TLS verification is disabled. Credentials could be intercepted by a man-in-the-middle; install the device's CA in the platform trust store instead where possible.</Callout></div>}
          </div>
        )}
        <details className="rounded-md border border-slate-200 p-3 dark:border-slate-800">
          <summary className="cursor-pointer text-sm font-medium">Inventory details (vendor, model, serial, owner…)</summary>
          <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
            {T("vendor", "Vendor")}{T("model", "Model")}{T("os_name", "Operating system")}{T("os_version", "OS version")}
            {T("firmware", "Firmware")}{T("serial_number", "Serial number")}{T("owner", "Owner")}{T("department", "Department")}
            <div className="sm:col-span-2"><Field label="Notes" htmlFor="d-notes"><textarea id="d-notes" className="input" rows={2} value={f.notes} onChange={(e) => set("notes", e.target.value)} /></Field></div>
          </div>
          <p className="mt-2 text-xs text-slate-500">Empty fields are filled automatically from the device on the first successful connectivity test.</p>
        </details>
        {meta?.mode !== "production" && !device && (
          <label className="flex items-center gap-2 text-sm text-violet-700 dark:text-violet-300"><input type="checkbox" checked={f.is_simulated} onChange={(e) => set("is_simulated", e.target.checked)} />
            Simulated demo device (no real connection is made)</label>
        )}
      </form>
    </Modal>
  );
}
