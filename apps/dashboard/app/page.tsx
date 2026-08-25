async function apiHealth(): Promise<string> {
  try {
    const response = await fetch(`${process.env.AUTHFORGE_API_URL ?? "http://api:8000"}/health`, { cache: "no-store" });
    return response.ok ? "Operational" : "Unavailable";
  } catch { return "Unavailable"; }
}
export default async function Home() {
  const status = await apiHealth();
  return <main><p className="eyebrow">AUTHFORGE</p><h1>Identity infrastructure,<br />under your control.</h1><p className="lede">A clean installation contains no fabricated users, sessions, or events.</p><section><span>API</span><strong>{status}</strong></section><p>Create the first instance administrator through the setup API once bootstrap is enabled.</p></main>;
}

