import { ApiError, api, session } from "../lib/api";
import { toServerPerm } from "../lib/auth";

describe("api client", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("sends the anti-CSRF header and same-origin credentials", async () => {
    const f = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ ok: 1 }), { status: 200, headers: { "content-type": "application/json" } }));
    const r = await api<{ ok: number }>("/api/x", { body: { a: 1 } });
    expect(r.ok).toBe(1);
    const init = f.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ "X-Requested-With": "InfraPilot", "Content-Type": "application/json" });
    expect(init.credentials).toBe("same-origin");
    expect(init.method).toBe("POST");
  });

  it("normalises server errors into ApiError with field errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: { code: "validation_failed", message: "bad", errors: [{ field: "hostname", message: "required" }] } }),
      { status: 422, headers: { "content-type": "application/json" } }));
    const e = (await api("/api/x").catch((x) => x)) as ApiError;
    expect(e).toMatchObject({ status: 422, code: "validation_failed", message: "bad" });
    expect(e.fieldErrors[0].field).toBe("hostname");
  });

  it("notifies listeners when the session expires", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 401, headers: { "content-type": "application/json" } }));
    const fn = vi.fn();
    const off = session.onExpired(fn);
    await api("/api/devices").catch(() => null);
    expect(fn).toHaveBeenCalledTimes(1);
    off();
  });

  it("reports network failures clearly", async () => {
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new TypeError("Failed to fetch"));
    const e = (await api("/api/x").catch((x) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.message).toMatch(/Cannot reach the server/);
  });

  it("maps UI permission names to server codes", () => {
    expect(toServerPerm("devices.write")).toBe("devices:write");
    expect(toServerPerm("emergency.execute")).toBe("changes:emergency");
  });
});
