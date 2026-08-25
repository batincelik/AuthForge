export class AuthForgeError extends Error {
    status;
    code;
    requestId;
    constructor(status, code, message, requestId) {
        super(message);
        this.status = status;
        this.code = code;
        this.requestId = requestId;
    }
}
export class AuthForge {
    options;
    requestFetch;
    constructor(options) {
        this.options = options;
        this.requestFetch = options.fetch ?? globalThis.fetch;
        if (!this.requestFetch)
            throw new Error("A Fetch implementation is required");
    }
    async request(path, init = {}) {
        const headers = new Headers(init.headers);
        headers.set("Accept", "application/json");
        if (init.body)
            headers.set("Content-Type", "application/json");
        if (this.options.apiKey)
            headers.set("Authorization", `Bearer ${this.options.apiKey}`);
        const response = await this.requestFetch(`${this.options.baseUrl.replace(/\/$/, "")}${path}`, { ...init, headers });
        if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new AuthForgeError(response.status, body.error?.code ?? "HTTP_ERROR", body.error?.message ?? "AuthForge request failed", body.error?.request_id);
        }
        return (response.status === 204 ? undefined : await response.json());
    }
    service = { application: () => this.request("/api/v1/service/application") };
    auth = {
        register: (email, password) => this.request("/api/v1/auth/register", { method: "POST", body: JSON.stringify({ email, password }) }),
        login: (email, password) => this.request("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
        refresh: (refreshToken) => this.request("/api/v1/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) }),
    };
}
