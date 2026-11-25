import { describe, expect, it } from "vitest";
import { toTables } from "../components/ManageConsole";
import { initialValues } from "../components/SchemaForm";

describe("toTables", () => {
  it("renders a list of objects as one table", () => {
    const t = toTables([{ unit: "nginx", active: "active" }]);
    expect(t).toHaveLength(1);
    expect(t[0].rows[0].unit).toBe("nginx");
  });
  it("splits objects into summary and nested tables", () => {
    const t = toTables({ hostname: "h1", interfaces: [{ name: "eth0" }], routes: [] });
    expect(t.map((x) => x.name)).toEqual(["Summary", "Interfaces"]);
  });
  it("returns nothing for plain text output", () => {
    expect(toTables(null)).toEqual([]);
    expect(toTables({ simulated: true, params: {} })).toHaveLength(1);
  });
});

describe("initialValues row pre-fill", () => {
  const schema = { type: "object", properties: { packages: { type: "array", items: { type: "string" } }, name: { type: "string" } } };
  it("wraps a scalar row value for list fields and stringifies numbers", () => {
    expect(initialValues(schema, { packages: "openssl", name: 42 })).toEqual({ packages: ["openssl"], name: "42" });
  });
});

import { palette } from "../lib/branding";
describe("brand palette", () => {
  it("uses the chosen colour as shade 600 and gets lighter/darker around it", () => {
    const p = palette("#0f766e")!;
    expect(p[600]).toEqual([15, 118, 110]);
    expect(p[50][0]).toBeGreaterThan(p[300][0]);
    expect(p[900][1]).toBeLessThan(p[600][1]);
    expect(palette("red")).toBeNull();
  });
});
