export interface AuthForgeOptions { baseUrl: string; apiKey?: string; fetch?: typeof globalThis.fetch }
export interface Application { id: string; name: string; slug: string; description: string | null; application_type: "web" | "spa" | "mobile" | "server" | "machine" }
export interface TokenResponse { access_token: string; refresh_token: string; token_type: "Bearer"; expires_in: number }
export interface AuthForgeErrorBody { error?: { code?: string; message?: string; request_id?: string } }

export class AuthForgeError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string, public readonly requestId?: string) { super(message); }
}

export class AuthForge {
  private readonly requestFetch: typeof globalThis.fetch;
  constructor(private readonly options: AuthForgeOptions) {
    this.requestFetch = options.fetch ?? globalThis.fetch;
    if (!this.requestFetch) throw new Error("A Fetch implementation is required");
  }
  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body) headers.set("Content-Type", "application/json");
    if (this.options.apiKey) headers.set("Authorization", `Bearer ${this.options.apiKey}`);
    const response = await this.requestFetch(`${this.options.baseUrl.replace(/\/$/, "")}${path}`, { ...init, headers });
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as AuthForgeErrorBody;
      throw new AuthForgeError(response.status, body.error?.code ?? "HTTP_ERROR", body.error?.message ?? "AuthForge request failed", body.error?.request_id);
    }
    return (response.status === 204 ? undefined : await response.json()) as T;
  }
  readonly service = { application: (): Promise<Application> => this.request<Application>("/api/v1/service/application") };
  readonly auth = {
    register: (email: string, password: string) => this.request("/api/v1/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),
    login: (email: string, password: string): Promise<TokenResponse> => this.request("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
    refresh: (refreshToken: string): Promise<TokenResponse> => this.request("/api/v1/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) }),
  };
}

