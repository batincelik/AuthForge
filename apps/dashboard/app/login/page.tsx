"use client";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";

const api = process.env.NEXT_PUBLIC_AUTHFORGE_API_URL ?? "http://localhost:8000";
export default function Login() {
  const router = useRouter();
  const [error, setError] = useState("");
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError("");
    const data = new FormData(event.currentTarget);
    const response = await fetch(`${api}/api/v1/auth/login`, { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: data.get("email"), password: data.get("password") }) });
    if (!response.ok) { const body = await response.json(); setError(body.error?.message ?? "Login failed"); return; }
    router.push("/dashboard");
  }
  return <main><p className="eyebrow">AUTHFORGE ADMIN</p><h1>Sign in</h1><form onSubmit={submit}><label>Email<input name="email" type="email" autoComplete="username" required /></label><label>Password<input name="password" type="password" autoComplete="current-password" required /></label>{error && <p role="alert" className="error">{error}</p>}<button type="submit">Continue</button></form></main>;
}

