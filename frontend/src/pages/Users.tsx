import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Lock, Pencil, Plus, ShieldOff, Unlock, UserPlus } from "lucide-react";
import { FormEvent, useState } from "react";
import { Badge, Button, Card, ErrorBox, Field, Modal, PageHeader, Skeleton, Tabs, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { fmtDate } from "../lib/format";
import type { Group, Me, Role } from "../lib/types";

type RoleAssign = { role_id: number; scope_group_id: number | null };

function RoleEditor({ value, onChange, roles, groups }: { value: RoleAssign[]; onChange: (v: RoleAssign[]) => void; roles: Role[]; groups: Group[] }) {
  return (
    <div className="space-y-2">
      {value.map((r, i) => (
        <div key={i} className="flex gap-2">
          <select className="input" aria-label="Role" value={r.role_id} onChange={(e) => onChange(value.map((x, j) => (j === i ? { ...x, role_id: Number(e.target.value) } : x)))}>
            {roles.map((ro) => <option key={ro.id} value={ro.id}>{ro.name}</option>)}</select>
          <select className="input" aria-label="Scope" value={r.scope_group_id ?? ""} onChange={(e) => onChange(value.map((x, j) => (j === i ? { ...x, scope_group_id: e.target.value ? Number(e.target.value) : null } : x)))}>
            <option value="">All devices (global)</option>{groups.map((g) => <option key={g.id} value={g.id}>Only group: {g.name}</option>)}</select>
          <Button variant="ghost" type="button" onClick={() => onChange(value.filter((_, j) => j !== i))} aria-label="Remove role">✕</Button>
        </div>
      ))}
      <Button variant="outline" size="sm" type="button" onClick={() => roles[0] && onChange([...value, { role_id: roles[0].id, scope_group_id: null }])}>Add role</Button>
    </div>
  );
}

function UserForm({ user, roles, groups, onClose }: { user?: Me; roles: Role[]; groups: Group[]; onClose: () => void }) {
  const [f, setF] = useState({ username: user?.username || "", display_name: user?.display_name || "", email: user?.email || "", password: "" });
  const [assign, setAssign] = useState<RoleAssign[]>(user?.roles.map((r) => ({ role_id: r.role_id, scope_group_id: r.scope_group_id })) || []);
  const [err, setErr] = useState<unknown>(null); const qc = useQueryClient(); const toast = useToast();
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try {
      if (user) await api(`/api/users/${user.id}`, { method: "PATCH", body: { display_name: f.display_name, email: f.email || null, roles: assign } });
      else await api("/api/users", { body: { ...f, email: f.email || null, roles: assign, must_change_password: true } });
      qc.invalidateQueries({ queryKey: ["users"] }); toast({ tone: "success", title: user ? "User updated" : "User created", body: user ? undefined : "They must change the password at first sign-in." }); onClose();
    } catch (e2) { setErr(e2); }
  };
  return (
    <Modal open onClose={onClose} title={user ? `Edit ${user.username}` : "Create local user"} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="uf" type="submit">Save</Button></>}>
      <form id="uf" onSubmit={submit} className="space-y-3"><ErrorBox error={err} />
        {!user && <Field label="Username" required><input className="input" required value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>}
        <Field label="Display name"><input className="input" value={f.display_name} onChange={(e) => setF({ ...f, display_name: e.target.value })} /></Field>
        <Field label="E-mail"><input type="email" className="input" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
        {!user && <Field label="Temporary password" required hint="12+ characters; the user must change it at first sign-in."><input type="password" className="input" required autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>}
        <Field label="Roles" hint="Scope a role to a device group to limit which devices it applies to."><RoleEditor value={assign} onChange={setAssign} roles={roles} groups={groups} /></Field>
        {user?.auth_source === "ldap" && <p className="text-xs text-amber-600">Directory users: global roles are re-synchronised from AD group membership at each sign-in.</p>}
      </form>
    </Modal>
  );
}

function RoleForm({ role, perms, onClose }: { role?: Role; perms: { code: string; module: string; description: string }[]; onClose: () => void }) {
  const [name, setName] = useState(role?.name || ""); const [description, setDescription] = useState(role?.description || "");
  const [sel, setSel] = useState<string[]>(role?.permissions || []);
  const [err, setErr] = useState<unknown>(null); const qc = useQueryClient();
  const modules = [...new Set(perms.map((p) => p.module))];
  const submit = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api(role ? `/api/roles/${role.id}` : "/api/roles", { method: role ? "PUT" : "POST", body: { name, description, permissions: sel } }); qc.invalidateQueries({ queryKey: ["roles"] }); onClose(); }
    catch (e2) { setErr(e2); }
  };
  return (
    <Modal open size="lg" onClose={onClose} title={role ? `Edit role ${role.name}` : "Create custom role"} footer={<><Button variant="outline" onClick={onClose}>Cancel</Button><Button form="rlf" type="submit">Save</Button></>}>
      <form id="rlf" onSubmit={submit} className="space-y-3"><ErrorBox error={err} />
        <div className="grid grid-cols-2 gap-3"><Field label="Name" required><input className="input" required value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Description"><input className="input" value={description} onChange={(e) => setDescription(e.target.value)} /></Field></div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">{modules.map((m) => (
          <fieldset key={m} className="rounded-md border border-slate-200 p-2 dark:border-slate-700"><legend className="px-1 text-xs font-semibold uppercase text-slate-500">{m}</legend>
            {perms.filter((p) => p.module === m).map((p) => (
              <label key={p.code} className="flex items-start gap-2 py-0.5 text-sm"><input type="checkbox" className="mt-1" checked={sel.includes(p.code)} onChange={() => setSel(sel.includes(p.code) ? sel.filter((x) => x !== p.code) : [...sel, p.code])} />
                <span>{p.description}<span className="block font-mono text-[10px] text-slate-400">{p.code}</span></span></label>))}
          </fieldset>))}</div>
      </form>
    </Modal>
  );
}

export default function UsersPage() {
  const [tab, setTab] = useState<"users" | "roles">("users");
  const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const { data: users, isLoading, error } = useQuery({ queryKey: ["users"], queryFn: () => api<Me[]>("/api/users") });
  const { data: roles } = useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/api/roles") });
  const { data: perms } = useQuery({ queryKey: ["permissions"], queryFn: () => api<{ code: string; module: string; description: string }[]>("/api/permissions") });
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const [edit, setEdit] = useState<Me | null | undefined>(undefined);
  const [roleEdit, setRoleEdit] = useState<Role | null | undefined>(undefined);
  const [resetFor, setResetFor] = useState<Me | null>(null);
  const [pw, setPw] = useState("");
  const action = async (u: Me, path: string, title: string, msg: string) => {
    if (!(await confirm({ title, message: msg, danger: true }))) return;
    try { await api(`/api/users/${u.id}/${path}`, { method: "POST" }); qc.invalidateQueries({ queryKey: ["users"] }); toast({ tone: "success", title: "Done" }); }
    catch (e) { toast({ tone: "error", title: "Failed", body: (e as Error).message }); }
  };
  const toggleActive = async (u: Me) => {
    if (!(await confirm({ title: u.is_active ? "Disable user?" : "Enable user?", message: u.is_active ? "Active sessions are revoked immediately." : "", danger: u.is_active }))) return;
    try { await api(`/api/users/${u.id}`, { method: "PATCH", body: { is_active: !u.is_active } }); qc.invalidateQueries({ queryKey: ["users"] }); }
    catch (e) { toast({ tone: "error", title: "Failed", body: (e as Error).message }); }
  };
  const doReset = async (e: FormEvent) => {
    e.preventDefault();
    try { await api(`/api/users/${resetFor!.id}/reset-password`, { body: { new_password: pw } }); toast({ tone: "success", title: "Password reset", body: "The user must change it at next sign-in." }); setResetFor(null); setPw(""); }
    catch (e2) { toast({ tone: "error", title: "Reset failed", body: (e2 as Error).message }); }
  };
  const gname = (id: number | null) => (id ? groups?.find((g) => g.id === id)?.name || `group ${id}` : null);
  return (
    <div>
      <PageHeader title="Users & roles" subtitle="Local and Active Directory users, role-based permissions and device-group scoping."
        actions={tab === "users" ? <Button icon={<UserPlus className="h-4 w-4" />} onClick={() => setEdit(null)}>Create user</Button> : <Button icon={<Plus className="h-4 w-4" />} onClick={() => setRoleEdit(null)}>Custom role</Button>} />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "users", label: "Users" }, { id: "roles", label: "Roles & permissions" }]} />
      {tab === "users" && (error ? <ErrorBox error={error} /> : isLoading ? <Skeleton /> : (
        <Card padded={false}><div className="overflow-x-auto"><table className="w-full min-w-[900px]">
          <thead className="bg-slate-50 dark:bg-slate-900/60"><tr><th className="th">User</th><th className="th">Source</th><th className="th">Roles</th><th className="th">MFA</th><th className="th">Status</th><th className="th">Last sign-in</th><th className="th" /></tr></thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800">{(users || []).map((u) => (
            <tr key={u.id}><td className="td"><p className="font-medium">{u.display_name || u.username}</p><p className="text-xs text-slate-500">{u.username}{u.email && ` · ${u.email}`}</p></td>
              <td className="td"><Badge tone={u.auth_source === "ldap" ? "blue" : "gray"}>{u.auth_source === "ldap" ? "Active Directory" : "Local"}</Badge></td>
              <td className="td"><div className="flex flex-wrap gap-1">{u.roles.map((r) => <Badge key={r.id} tone="violet">{r.role}{r.scope_group_id && ` @ ${gname(r.scope_group_id)}`}</Badge>)}{!u.roles.length && <span className="text-xs text-slate-400">none</span>}</div></td>
              <td className="td">{u.mfa_enabled ? <Badge tone="green">on</Badge> : <Badge>off</Badge>}</td>
              <td className="td">{!u.is_active ? <Badge tone="red">disabled</Badge> : u.locked ? <Badge tone="red"><Lock className="h-3 w-3" />locked</Badge> : <Badge tone="green">active</Badge>}</td>
              <td className="td text-xs text-slate-500">{fmtDate(u.last_login_at)}</td>
              <td className="td"><div className="flex justify-end gap-1">
                <Button size="sm" variant="ghost" title="Edit" aria-label="Edit user" onClick={() => setEdit(u)}><Pencil className="h-4 w-4" /></Button>
                {u.auth_source === "local" && <Button size="sm" variant="ghost" title="Reset password" aria-label="Reset password" onClick={() => setResetFor(u)}><KeyRound className="h-4 w-4" /></Button>}
                {u.locked && <Button size="sm" variant="ghost" title="Unlock" aria-label="Unlock" onClick={() => action(u, "unlock", "Unlock account?", u.username)}><Unlock className="h-4 w-4" /></Button>}
                {u.mfa_enabled && <Button size="sm" variant="ghost" title="Reset MFA" aria-label="Reset MFA" onClick={() => action(u, "reset-mfa", "Reset MFA?", "The user will need to enrol their authenticator again.")}><ShieldOff className="h-4 w-4" /></Button>}
                <Button size="sm" variant="outline" onClick={() => toggleActive(u)}>{u.is_active ? "Disable" : "Enable"}</Button>
              </div></td></tr>
          ))}</tbody></table></div></Card>
      ))}
      {tab === "roles" && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">{(roles || []).map((r) => (
          <Card key={r.id} title={<span className="flex items-center gap-2">{r.name}{r.is_builtin && <Badge>built-in</Badge>}</span>} actions={!r.is_builtin && <Button size="sm" variant="outline" onClick={() => setRoleEdit(r)}>Edit</Button>}>
            <p className="mb-2 text-sm text-slate-500">{r.description}</p>
            <div className="flex flex-wrap gap-1">{r.permissions.map((p) => <span key={p} className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[10px] dark:bg-slate-800">{p}</span>)}</div>
          </Card>))}</div>
      )}
      {edit !== undefined && roles && groups && <UserForm user={edit || undefined} roles={roles} groups={groups} onClose={() => setEdit(undefined)} />}
      {roleEdit !== undefined && perms && <RoleForm role={roleEdit || undefined} perms={perms} onClose={() => setRoleEdit(undefined)} />}
      {resetFor && <Modal open size="sm" onClose={() => setResetFor(null)} title={`Reset password for ${resetFor.username}`} footer={<><Button variant="outline" onClick={() => setResetFor(null)}>Cancel</Button><Button form="rp" type="submit">Reset</Button></>}>
        <form id="rp" onSubmit={doReset}><Field label="Temporary password" hint="All sessions of this user are revoked."><input type="password" className="input" required autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} /></Field></form>
      </Modal>}
    </div>
  );
}
