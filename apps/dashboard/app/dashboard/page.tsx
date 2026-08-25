"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type User = { id: string; email: string; status: string; email_verified_at: string | null };
type Application = { id: string; name: string; slug: string; application_type: string };
type Organization = { id: string; name: string; slug: string };
type Session = { id: string; last_seen_at: string; revoked_at: string | null; ip_address: string | null; user_agent: string | null; current: boolean };
type ApiKey = { id: string; name: string; prefix: string; scopes: string[]; revoked_at: string | null };
type SecurityEvent = { id: string; event_type: string; created_at: string; user_id: string | null };
type AuditEvent = { id: string; action: string; target_type: string; target_id: string; created_at: string };
const api = process.env.NEXT_PUBLIC_AUTHFORGE_API_URL ?? "http://localhost:8000";

export default function Dashboard() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [applications, setApplications] = useState<Application[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [revealedSecret, setRevealedSecret] = useState("");
  const [error, setError] = useState("");

  async function load() {
    const options = { credentials: "include" as const };
    const paths = ["/api/v1/me", "/api/v1/applications", "/api/v1/organizations", "/api/v1/me/sessions", "/api/v1/users", "/api/v1/api-keys", "/api/v1/security-events", "/api/v1/audit-events"];
    const responses = await Promise.all(paths.map(path => fetch(`${api}${path}`, options)));
    if (responses[0].status === 401) { router.replace("/login"); return; }
    if (responses.some(response => !response.ok)) { setError("Dashboard data could not be loaded."); return; }
    const [me, apps, orgs, active, userRows, keyRows, securityRows, auditRows] = await Promise.all(responses.map(response => response.json()));
    setUser(me); setApplications(apps); setOrganizations(orgs); setSessions(active);
    setUsers(userRows); setKeys(keyRows); setSecurityEvents(securityRows); setAuditEvents(auditRows);
  }
  useEffect(() => { void load(); }, []);

  async function mutate(path: string, method: "POST" | "DELETE") {
    const response = await fetch(`${api}${path}`, { method, credentials: "include" });
    if (!response.ok) setError("The security action could not be completed.");
    return response;
  }
  async function revokeSession(id: string) { if ((await mutate(`/api/v1/me/sessions/${id}`, "DELETE")).ok) void load(); }
  async function logout() { await mutate("/api/v1/auth/logout", "POST"); router.replace("/login"); }
  async function setDisabled(id: string, disabled: boolean) { if ((await mutate(`/api/v1/users/${id}/${disabled ? "disable" : "enable"}`, "POST")).ok) void load(); }
  async function revokeKey(id: string) { if ((await mutate(`/api/v1/api-keys/${id}`, "DELETE")).ok) void load(); }
  async function rotateKey(id: string) {
    const response = await mutate(`/api/v1/api-keys/${id}/rotate`, "POST");
    if (response.ok) { setRevealedSecret((await response.json()).secret); void load(); }
  }

  if (!user) return <main><p>{error || "Loading authenticated state…"}</p></main>;
  return <main className="wide">
    <header><div><p className="eyebrow">AUTHFORGE</p><h1>Security console</h1></div><button onClick={logout}>Sign out</button></header>
    <p>Signed in as {user.email}</p>{error && <p role="alert" className="error">{error}</p>}
    {revealedSecret && <section role="status"><strong>Copy this replacement key now. It will not be shown again.</strong><code>{revealedSecret}</code><button onClick={() => setRevealedSecret("")}>Dismiss</button></section>}
    <h2>Users</h2><table><thead><tr><th>Email</th><th>Status</th><th>Verified</th><th /></tr></thead><tbody>{users.map(item => <tr key={item.id}><td>{item.email}</td><td>{item.status}</td><td>{item.email_verified_at ? "Yes" : "No"}</td><td>{item.id !== user.id && <button onClick={() => setDisabled(item.id, item.status !== "disabled")}>{item.status === "disabled" ? "Enable" : "Disable"}</button>}</td></tr>)}</tbody></table>
    <h2>Applications</h2>{applications.length === 0 ? <p>Create your first application.</p> : <table><thead><tr><th>Name</th><th>Slug</th><th>Type</th></tr></thead><tbody>{applications.map(item => <tr key={item.id}><td>{item.name}</td><td>{item.slug}</td><td>{item.application_type}</td></tr>)}</tbody></table>}
    <h2>Organizations</h2>{organizations.length === 0 ? <p>No organizations yet.</p> : <table><thead><tr><th>Name</th><th>Slug</th></tr></thead><tbody>{organizations.map(item => <tr key={item.id}><td>{item.name}</td><td>{item.slug}</td></tr>)}</tbody></table>}
    <h2>Sessions</h2><table><thead><tr><th>Device</th><th>IP</th><th>Last active</th><th>Status</th><th /></tr></thead><tbody>{sessions.map(item => <tr key={item.id}><td>{item.user_agent ?? "Unknown device"}</td><td>{item.ip_address ?? "Unknown"}</td><td>{new Date(item.last_seen_at).toLocaleString()}</td><td>{item.revoked_at ? "Revoked" : item.current ? "Current" : "Active"}</td><td>{!item.revoked_at && !item.current && <button onClick={() => revokeSession(item.id)}>Revoke</button>}</td></tr>)}</tbody></table>
    <h2>API keys</h2><table><thead><tr><th>Name</th><th>Key</th><th>Scopes</th><th>Status</th><th /></tr></thead><tbody>{keys.map(item => <tr key={item.id}><td>{item.name}</td><td>{item.prefix}••••••••</td><td>{item.scopes.join(", ")}</td><td>{item.revoked_at ? "Revoked" : "Active"}</td><td>{!item.revoked_at && <><button onClick={() => rotateKey(item.id)}>Rotate</button> <button onClick={() => revokeKey(item.id)}>Revoke</button></>}</td></tr>)}</tbody></table>
    <h2>Security events</h2><table><thead><tr><th>Event</th><th>User</th><th>Time</th></tr></thead><tbody>{securityEvents.map(item => <tr key={item.id}><td>{item.event_type}</td><td>{item.user_id ?? "System"}</td><td>{new Date(item.created_at).toLocaleString()}</td></tr>)}</tbody></table>
    <h2>Audit logs</h2><table><thead><tr><th>Action</th><th>Target</th><th>Time</th></tr></thead><tbody>{auditEvents.map(item => <tr key={item.id}><td>{item.action}</td><td>{item.target_type}:{item.target_id}</td><td>{new Date(item.created_at).toLocaleString()}</td></tr>)}</tbody></table>
  </main>;
}
