import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Eye, Play, Siren } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, api } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { Job, Operation } from "../lib/types";
import { SchemaForm, cleanValues, initialValues } from "./SchemaForm";
import { Badge, Button, Callout, ErrorBox, Field, Modal, RiskBadge, useConfirm, useToast } from "./ui";

type Preview = {
  operation: string; risk: string; mutating: boolean; summary: string; approval_required: boolean; approval_reason: string; rollback: string;
  check_mode_available: boolean; targets: { id: number; hostname: string; environment: string; allowed: boolean }[];
};

/** Collects parameters, shows exactly what will change (server-side preview), then submits the job. */
export function OperationRunner({ op, deviceIds, onClose, defaults = {} }: { op: Operation; deviceIds: number[]; onClose: () => void; defaults?: Record<string, unknown> }) {
  const [values, setValues] = useState(() => initialValues(op.schema, defaults));
  const [checkMode, setCheckMode] = useState(false);
  const [emergency, setEmergency] = useState(false);
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const { can } = useAuth();
  const nav = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const qc = useQueryClient();
  const fieldErrors = useMemo(() => {
    const out: Record<string, string> = {};
    if (err instanceof ApiError) err.fieldErrors.forEach((f) => { out[f.field.replace(/^params\./, "")] = f.message; });
    return out;
  }, [err]);

  const doPreview = async () => {
    setErr(null);
    try {
      setPreview(await api<Preview>("/api/jobs/preview", { body: { operation_id: op.id, device_ids: deviceIds, params: cleanValues(op.schema, values), check_mode: checkMode } }));
    } catch (e) { setErr(e); setPreview(null); }
  };

  const submit = useMutation({
    mutationFn: () => api<Job>("/api/jobs", { body: { operation_id: op.id, device_ids: deviceIds, params: cleanValues(op.schema, values), check_mode: checkMode, emergency, reason } }),
    onSuccess: (job) => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
      toast({ tone: "success", title: job.status === "pending_approval" ? "Submitted for approval" : "Job queued",
        body: job.status === "pending_approval" ? "An approver has been notified. The change runs after approval." : `Job #${job.id} will run shortly.` });
      onClose(); nav(`/jobs/${job.id}`);
    },
    onError: (e) => setErr(e),
  });

  const run = async () => {
    if (!preview) return;
    if (op.mutating && !checkMode) {
      const ok = await confirm({
        title: emergency ? "Execute EMERGENCY change?" : preview.approval_required ? "Submit change for approval?" : "Apply this change now?",
        message: <div className="space-y-2"><p>{preview.summary}</p><p>Targets: <b>{preview.targets.map((t) => t.hostname).join(", ")}</b></p>
          {emergency && <p className="text-red-600">This bypasses pre-approval and will be flagged for mandatory post-change review.</p>}</div>,
        confirmLabel: emergency ? "Execute now" : preview.approval_required ? "Submit for approval" : "Apply change",
        danger: op.risk === "critical" || emergency, requireText: op.risk === "critical" || emergency ? "CONFIRM" : undefined,
      });
      if (!ok) return;
    }
    submit.mutate();
  };

  const blocked = preview?.targets.some((t) => !t.allowed);
  return (
    <Modal open onClose={onClose} size="lg" title={<span className="flex items-center gap-2">{op.name} <RiskBadge risk={op.risk} /></span>}
      footer={<>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button variant="secondary" icon={<Eye className="h-4 w-4" />} onClick={doPreview}>Preview change</Button>
        <Button disabled={!preview || blocked || (preview.approval_required && !emergency && !checkMode && reason.trim().length < 3)} loading={submit.isPending}
          variant={emergency ? "danger" : "primary"} icon={emergency ? <Siren className="h-4 w-4" /> : <Play className="h-4 w-4" />} onClick={run}>
          {!op.mutating ? "Run" : checkMode ? "Run check (dry-run)" : emergency ? "Execute emergency change" : preview?.approval_required ? "Request approval" : "Apply"}
        </Button>
      </>}>
      <div className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">{op.summary.replace(/\{[^}]+\}/g, "…")} · <span className="text-slate-500">{deviceIds.length} target device(s)</span></p>
        <ErrorBox error={err} />
        <SchemaForm schema={op.schema} values={values} onChange={(v) => { setValues(v); setPreview(null); }} errors={fieldErrors} />
        {op.mutating && (
          <div className="flex flex-wrap gap-4 rounded-md border border-slate-200 p-3 text-sm dark:border-slate-800">
            {op.check_mode && <label className="flex items-center gap-2"><input type="checkbox" checked={checkMode} onChange={(e) => { setCheckMode(e.target.checked); setPreview(null); }} />
              Check mode (dry-run — report what would change, change nothing)</label>}
            {can("emergency.execute") && !checkMode && <label className="flex items-center gap-2 text-red-700 dark:text-red-400"><input type="checkbox" checked={emergency} onChange={(e) => setEmergency(e.target.checked)} />
              Emergency change (execute immediately, post-review)</label>}
          </div>
        )}
        {preview && (
          <div className="space-y-3">
            <Callout tone={preview.mutating && !checkMode ? "warning" : "info"} title="What will happen">
              <p className="mt-1">{checkMode ? "DRY-RUN: " : ""}{preview.summary}</p>
              <div className="mt-2 flex flex-wrap gap-1">{preview.targets.map((t) => <Badge key={t.id} tone={t.allowed ? (t.environment === "production" ? "amber" : "gray") : "red"}>{t.hostname} · {t.environment}{!t.allowed && " · no permission"}</Badge>)}</div>
              {preview.mutating && preview.rollback && <p className="mt-2 text-xs"><b>Rollback:</b> {preview.rollback}</p>}
            </Callout>
            {preview.approval_required && !checkMode && (
              <Callout tone="info" title={`Approval required — ${preview.approval_reason}`}>
                {emergency ? <p>Emergency: the change executes now and is queued for post-change review.</p> : <p>The change will run after another authorised user approves it.</p>}
              </Callout>
            )}
            {(preview.approval_required || emergency) && !checkMode && (
              <Field label={emergency ? "Emergency justification" : "Reason / change ticket"} required htmlFor="reason">
                <textarea id="reason" className="input" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. CHG0012345 — enable new VLAN for VoIP" />
              </Field>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
