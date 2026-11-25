import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { SchemaForm, cleanValues, initialValues } from "../components/SchemaForm";
import { Button, ConfirmProvider, ErrorBox, Pagination, StatusBadge, useConfirm } from "../components/ui";
import { ApiError } from "../lib/api";
import type { JsonSchema } from "../lib/types";

const schema: JsonSchema = {
  type: "object", required: ["name", "action", "password"],
  properties: {
    name: { type: "string", title: "Name", pattern: "^[a-z]+$" },
    action: { enum: ["start", "stop", "restart"], type: "string", title: "Action" },
    password: { type: "string", format: "password", writeOnly: true, title: "Password" },
    count: { type: "integer", minimum: 1, maximum: 10, default: 3, title: "Count" },
    enabled: { anyOf: [{ type: "boolean" }, { type: "null" }], default: null, title: "Enabled" },
    groups: { type: "array", items: { type: "string" }, title: "Groups" },
  },
};

function Harness({ onValues }: { onValues: (v: Record<string, unknown>) => void }) {
  const [v, setV] = useState(() => initialValues(schema));
  return <><SchemaForm schema={schema} values={v} onChange={(n) => { setV(n); onValues(n); }} /></>;
}

describe("StatusBadge", () => {
  it("renders human labels", () => {
    render(<StatusBadge status="pending_approval" />);
    expect(screen.getByText("Awaiting approval")).toBeInTheDocument();
  });
});

describe("SchemaForm", () => {
  it("renders correct controls from JSON schema", () => {
    render(<Harness onValues={() => {}} />);
    expect(screen.getByLabelText(/Action/)).toHaveProperty("tagName", "SELECT");
    expect(screen.getByLabelText(/Password/)).toHaveAttribute("type", "password");
    expect(screen.getByLabelText(/Count/)).toHaveValue(3);
    expect(screen.getByLabelText(/Enabled/)).toHaveProperty("tagName", "SELECT");
  });
  it("produces clean typed values", async () => {
    let last: Record<string, unknown> = {};
    render(<Harness onValues={(v) => (last = v)} />);
    await userEvent.type(screen.getByLabelText(/Name/), "nginx");
    await userEvent.type(screen.getByLabelText(/Groups/), "a, b");
    fireEvent.change(screen.getByLabelText(/Count/), { target: { value: "7" } });
    const out = cleanValues(schema, last);
    expect(out.name).toBe("nginx");
    expect(out.count).toBe(7);
    expect(out.groups).toEqual(["a", "b"]);
    expect("enabled" in out).toBe(false); // nullable left blank is omitted
  });
});

describe("ErrorBox", () => {
  it("shows field-level validation errors", () => {
    render(<ErrorBox error={new ApiError(422, "validation_error", "Some fields are invalid", { errors: [{ field: "hostname", message: "bad" }] })} />);
    expect(screen.getByRole("alert")).toHaveTextContent("hostname");
  });
  it("labels 403 as not permitted", () => {
    render(<ErrorBox error={new ApiError(403, "forbidden", "Missing permission: devices.write")} />);
    expect(screen.getByText("Not permitted")).toBeInTheDocument();
  });
});

describe("Pagination", () => {
  it("disables previous on first page and reports range", async () => {
    const onPage = vi.fn();
    render(<Pagination page={1} pageSize={25} total={60} onPage={onPage} />);
    expect(screen.getByText("1–25 of 60")).toBeInTheDocument();
    expect(screen.getByLabelText("Previous page")).toBeDisabled();
    await userEvent.click(screen.getByLabelText("Next page"));
    expect(onPage).toHaveBeenCalledWith(2);
  });
});

function ConfirmHarness({ onResult }: { onResult: (v: boolean) => void }) {
  const confirm = useConfirm();
  return <Button onClick={async () => onResult(await confirm({ title: "Danger", message: "Sure?", requireText: "CONFIRM", danger: true }))}>open</Button>;
}

describe("ConfirmDialog", () => {
  it("requires typed confirmation for critical actions", async () => {
    const onResult = vi.fn();
    render(<ConfirmProvider><ConfirmHarness onResult={onResult} /></ConfirmProvider>);
    await userEvent.click(screen.getByText("open"));
    const btn = screen.getByRole("button", { name: "Confirm" });
    expect(btn).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/to confirm/), "CONFIRM");
    expect(btn).toBeEnabled();
    await userEvent.click(btn);
    await waitFor(() => expect(onResult).toHaveBeenCalledWith(true));
  });
});
