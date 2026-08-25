import type { ReactNode } from "react";
import "./styles.css";

// CSP nonces are generated per request by proxy.ts, so pages must not reuse
// prerendered HTML that cannot carry the matching nonce.
export const dynamic = "force-dynamic";

export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
