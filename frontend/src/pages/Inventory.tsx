import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, FolderTree, Pencil, Plus, Trash2 } from "lucide-react";
import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { DevicePicker } from "../components/DevicePicker";
import { Button, Card, EmptyState, ErrorBox, Field, Modal, PageHeader, useConfirm, useToast } from "../components/ui";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Group, Site } from "../lib/types";

export default function Inventory() {
  const { can } = useAuth(); const qc = useQueryClient(); const confirm = useConfirm(); const toast = useToast();
  const { data: sites } = useQuery({ queryKey: ["sites"], queryFn: () => api<Site[]>("/api/sites") });
  const { data: groups } = useQuery({ queryKey: ["groups"], queryFn: () => api<Group[]>("/api/groups") });
  const [siteForm, setSiteForm] = useState<Partial<Site> | null>(null);
  const [groupForm, setGroupForm] = useState<Partial<Group> | null>(null);
  const [members, setMembers] = useState<Group | null>(null);
  const [memberIds, setMemberIds] = useState<number[]>([]);
  const [err, setErr] = useState<unknown>(null);

  const saveSite = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api(siteForm!.id ? `/api/sites/${siteForm!.id}` : "/api/sites", { method: siteForm!.id ? "PUT" : "POST", body: { name: siteForm!.name, kind: siteForm!.kind || "datacenter", location: siteForm!.location || "" } });
      qc.invalidateQueries({ queryKey: ["sites"] }); setSiteForm(null); } catch (e2) { setErr(e2); }
  };
  const saveGroup = async (e: FormEvent) => {
    e.preventDefault(); setErr(null);
    try { await api(groupForm!.id ? `/api/groups/${groupForm!.id}` : "/api/groups", { method: groupForm!.id ? "PUT" : "POST", body: { name: groupForm!.name, description: groupForm!.description || "" } });
      qc.invalidateQueries({ queryKey: ["groups"] }); setGroupForm(null); } catch (e2) { setErr(e2); }
  };
  const openMembers = async (g: Group) => {
    const r = await api<{ items: { id: number }[] }>(`/api/devices?group_id=${g.id}&page_size=200`);
    setMemberIds(r.items.map((d) => d.id)); setMembers(g);
  };
  const saveMembers = async () => {
    await api(`/api/groups/${members!.id}/members`, { body: { device_ids: memberIds, action: "set" } });
    qc.invalidateQueries({ queryKey: ["groups"] }); toast({ tone: "success", title: "Group membership saved" }); setMembers(null);
  };
  const remove = async (kind: "sites" | "groups", id: number, name: string) => {
    if (!(await confirm({ title: `Delete ${name}?`, message: kind === "sites" ? "Only empty sites can be deleted." : "Devices stay in the inventory; only the grouping is removed.", danger: true }))) return;
    try { await api(`/api/${kind}/${id}`, { method: "DELETE" }); qc.invalidateQueries({ queryKey: [kind] }); } catch (e) { toast({ tone: "error", title: "Cannot delete", body: (e as Error).message }); }
  };
  return (
    <div>
      <PageHeader title="Sites & groups" subtitle="Organise devices by datacenter/branch and by logical groups. Groups also scope role permissions, alert rules and maintenance windows." />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="Sites" padded={false} actions={can("devices.write") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setSiteForm({ kind: "datacenter" })}>Add site</Button>}>
          {!sites?.length ? <EmptyState icon={<Building2 className="h-6 w-6" />} title="No sites" /> : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">{sites.map((s) => (
              <li key={s.id} className="flex items-center justify-between px-4 py-2.5 text-sm"><div><Link to={`/devices?site_id=${s.id}`} className="font-medium hover:underline">{s.name}</Link>
                <p className="text-xs text-slate-500">{s.kind} · {s.location || "no location"} · {s.device_count} device(s)</p></div>
                {can("devices.write") && <div className="flex gap-1"><Button size="sm" variant="ghost" aria-label="Edit site" onClick={() => setSiteForm(s)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="sm" variant="ghost" aria-label="Delete site" onClick={() => remove("sites", s.id, s.name)}><Trash2 className="h-4 w-4" /></Button></div>}</li>))}</ul>)}
        </Card>
        <Card title="Device groups" padded={false} actions={can("devices.write") && <Button size="sm" icon={<Plus className="h-4 w-4" />} onClick={() => setGroupForm({})}>Add group</Button>}>
          {!groups?.length ? <EmptyState icon={<FolderTree className="h-6 w-6" />} title="No groups" /> : (
            <ul className="divide-y divide-slate-100 dark:divide-slate-800">{groups.map((g) => (
              <li key={g.id} className="flex items-center justify-between px-4 py-2.5 text-sm"><div><Link to={`/devices?group_id=${g.id}`} className="font-medium hover:underline">{g.name}</Link>
                <p className="text-xs text-slate-500">{g.description || "—"} · {g.device_count} device(s)</p></div>
                {can("devices.write") && <div className="flex gap-1"><Button size="sm" variant="outline" onClick={() => openMembers(g)}>Members</Button>
                  <Button size="sm" variant="ghost" aria-label="Edit group" onClick={() => setGroupForm(g)}><Pencil className="h-4 w-4" /></Button>
                  <Button size="sm" variant="ghost" aria-label="Delete group" onClick={() => remove("groups", g.id, g.name)}><Trash2 className="h-4 w-4" /></Button></div>}</li>))}</ul>)}
        </Card>
      </div>
      {siteForm && <Modal open onClose={() => setSiteForm(null)} title={siteForm.id ? "Edit site" : "Add site"} footer={<><Button variant="outline" onClick={() => setSiteForm(null)}>Cancel</Button><Button form="sf" type="submit">Save</Button></>}>
        <form id="sf" onSubmit={saveSite} className="space-y-3"><ErrorBox error={err} />
          <Field label="Name" required><input className="input" required value={siteForm.name || ""} onChange={(e) => setSiteForm({ ...siteForm, name: e.target.value })} /></Field>
          <Field label="Kind"><select className="input" value={siteForm.kind} onChange={(e) => setSiteForm({ ...siteForm, kind: e.target.value })}>{["datacenter", "branch", "office", "cloud"].map((k) => <option key={k}>{k}</option>)}</select></Field>
          <Field label="Location / address"><input className="input" value={siteForm.location || ""} onChange={(e) => setSiteForm({ ...siteForm, location: e.target.value })} /></Field>
        </form></Modal>}
      {groupForm && <Modal open onClose={() => setGroupForm(null)} title={groupForm.id ? "Edit group" : "Add group"} footer={<><Button variant="outline" onClick={() => setGroupForm(null)}>Cancel</Button><Button form="gf" type="submit">Save</Button></>}>
        <form id="gf" onSubmit={saveGroup} className="space-y-3"><ErrorBox error={err} />
          <Field label="Name" required><input className="input" required value={groupForm.name || ""} onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} /></Field>
          <Field label="Description"><input className="input" value={groupForm.description || ""} onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} /></Field>
        </form></Modal>}
      {members && <Modal open size="lg" onClose={() => setMembers(null)} title={`Members of ${members.name}`} footer={<><Button variant="outline" onClick={() => setMembers(null)}>Cancel</Button><Button onClick={saveMembers}>Save membership</Button></>}>
        <DevicePicker value={memberIds} onChange={setMemberIds} /></Modal>}
    </div>
  );
}
