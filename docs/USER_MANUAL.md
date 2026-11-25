# User Manual

## Signing in
Use your local or Active Directory account. If two-factor authentication is enabled, enter the
6-digit code from your authenticator app. After 5 failed attempts the account locks for 15 minutes.
Sessions end after 60 minutes of inactivity.

## Dashboard
* **Health badge** next to the title: *All systems operational*, *Degraded* (degraded devices or
  warnings) or *Action needed* (devices down or critical alerts).
* **KPI tiles** (click to drill down): devices up/down/degraded, 24-hour availability, open alerts by
  severity, changes in the last 24 h (succeeded / failed / awaiting approval) and configuration
  backup coverage (switches and firewalls backed up in the last 7 days).
* **Charts**: availability over 24 h, fleet health donut, 7-day activity (jobs by outcome and alerts
  raised), CPU / memory / disk average and peak with the busiest devices.
* **Sites** health bars, **active alerts**, **recent jobs**, and **Needs attention**: approvals
  waiting, devices not polled for 24 h, devices never backed up, next scheduled runs.
* A purple banner and "Simulated" badges mean demo mode — those devices are not real.

## Managing a device (Manage tab)
Open a device and choose **Manage** (or click **Manage** in the device list).
1. Pick a view on the left — e.g. *List services*, *Top processes*, *Pending updates*, *Firewall
   policies*, *Virtual machines*. The result appears as a sortable, filterable table you can export
   to CSV; *Show raw output* shows the device's original text.
2. Rows offer **actions** that fit their state: Start / Stop / Restart a service, End or Kill a
   process, Unlock / Reset password / Disable an AD user, Run / Enable / Disable a scheduled task,
   Install / Uninstall a Windows feature, Shut down / Enable a switch port, Enable / Disable / Delete a
   firewall policy, Start / Shut down / Reboot / Snapshot a VM, Roll back / Delete a snapshot, Upgrade
   a pending package. Read-only actions (Details, Logs, Snapshots, Leases…) open directly in the console.
3. Changing actions open the normal change dialog with the fields pre-filled from the row. Nothing
   runs until you preview and confirm, approval policies apply, and critical actions require typing
   CONFIRM. Buttons you lack permission for are disabled.
4. Views that list things you can add to show a **New…/Add rule** button above the table.
5. **Host firewalls**: on Windows open *List firewall rules* (Edit, Enable/Disable, Delete per rule;
   *Add rule* to create one); on Linux open *Firewall rules* (ufw or firewalld; Delete per rule, *Add
   rule* for allow/deny/reject by port, protocol and optional source). The job page shows the rule
   set before and after the change and how to undo it.
6. **Start a change…** at the bottom left lists every change operation for the device (e.g. reboot,
   create VLAN, save configuration).

## Devices
* **Search and filter** by name/IP/serial, type, environment, status, site, group or tag; save a filter
  for reuse; sort columns; export to CSV/Excel.
* **Register** a device (Devices → Add): hostname, address, type, driver, environment, site,
  credential(s), tags. **Import** many from CSV/Excel — download the template, upload, review the
  validation result (nothing is imported if any row is invalid), then import.
* **Test connectivity** runs ICMP, the management-port check and an authenticated driver login, and
  fills empty inventory fields (OS, model, serial, firmware) from the device.
* The **device page** shows details, live health and charts, available operations, job history,
  configuration backups (view / compare two versions) and alerts.

## Running operations
1. Device → Operations (or select several devices → Run operation).
2. Fill in the form; operations marked read-only run immediately and show the result.
3. For changes click **Preview change**: you see exactly what will be changed, on which devices,
   whether approval or a maintenance window is required and whether you have permission.
4. Optional **Check mode** (dry-run) reports what would change without changing anything.
5. Confirm. Critical changes ask you to type CONFIRM. If approval is needed, give a reason or ticket.
6. Follow progress on the job page: per-device status, output, verification, before/after state,
   configuration diff and rollback instructions. Queued or waiting jobs can be cancelled; a running
   job stops after the current device.

Status meanings: `queued`, `running`, `pending_approval`, `waiting_window` (approved, waiting for a
maintenance window), `succeeded`, `partial` (some devices failed), `failed`, `cancelled`, `rejected`.
Per device, `unsupported` means the device/driver cannot perform that operation — nothing was changed.

## Automation
Job templates run a predefined operation or an approved Ansible playbook against selected devices,
with dry-run where supported. "Approved commands" lists the only Linux maintenance commands that can
be run through automation.

## Scripts (PowerShell, shell, switch and FortiGate CLI)
Operations → **Scripts** is a library of your own scripts:

| Runs on | Write | Parameters |
|---|---|---|
| Windows servers | PowerShell | used as variables, e.g. `$service` (InfraPilot declares and binds them — don't write `param()`) |
| Linux servers | bash | used as quoted variables, e.g. `"$app"`; tick *Run with sudo* if root is needed |
| Switches / routers (Cisco, Aruba CX, HP, TP-Link, MikroTik) | config lines (or show commands in read-only mode) | `{{name}}` placeholders |
| FortiGate | FortiOS CLI | `{{name}}` placeholders |

1. **Write** (users with *scripts:manage* — the Windows/Linux/Network/Firewall administrator roles):
   *New script*, choose where it runs, paste the script, add the parameters operators fill in
   (types: string, int, bool, IPv4, CIDR, hostname, interface, VLAN, choice) and describe how to undo it.
2. **Review**: a different user with *scripts:approve* (Super/Infrastructure Administrator) approves
   that exact version. Editing the script or its parameters later sends it back for review.
3. **Run**: *Run* → pick devices, fill in the values, **Preview** shows exactly what will be sent;
   optionally *Dry run*. The run is an ordinary job: approval policies, maintenance windows and the
   audit log apply; switches and firewalls get a configuration backup before and after (also when the
   device rejects a line part-way through), viewable under the device's Config backups.

Safety: values are checked by type and can never contain line breaks, so they cannot add commands;
lines such as `reload`, `write erase`, `format`, `no ip ssh` or `execute factoryreset` are refused
in scripts. FortiGate scripts are uploaded through the FortiOS configuration-script API, which does
not return CLI output — the job shows the configuration diff instead. Sophos XGS has no CLI-script
API, so scripts are not offered for Sophos.

## Schedules
Operations → **Schedules** runs an operation or playbook on a recurring basis (e.g. a nightly switch
configuration backup or a weekly pending-updates report). Choose the operation, its parameters, the
devices and a cron expression in **UTC** (presets provided; the form shows the next run times). Each
run is created as the schedule owner and goes through the same permission checks and approval
policies as a manual job — a scheduled change that needs approval waits for an approver. Operations
that take a password cannot be scheduled. **Run now** starts a run immediately; the table shows the
last run's job and any error. If the owner is disabled or loses permission, the schedule pauses itself.

## Reports
Overview → **Reports**: inventory summary, configuration backup coverage, firewall rule risk (from
the latest *Analyse policies* run per firewall), changes executed, alerts and job outcomes. Choose a
period where relevant, view on screen, or download CSV / Excel (exports are audited). Reports only
include devices you are allowed to see.

## Approvals
Approvers see pending requests with the change summary, targets, risk and reason. Approve or reject
with a note (a note is required to reject). You cannot approve your own request. Emergency changes
appear as "post review" — accept or flag them after the fact.

## Alerts and notifications
Alerts lists open/acknowledged/resolved alerts; acknowledge to stop escalation, resolve when fixed.
The bell icon shows your notifications (approval requests, job results, critical alerts).

## Your account
Settings → My account: change password, enable or disable two-factor authentication (disabling may
be blocked by policy).
