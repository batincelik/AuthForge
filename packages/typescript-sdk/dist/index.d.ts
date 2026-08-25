export interface AuthForgeOptions {
    baseUrl: string;
    apiKey?: string;
    fetch?: typeof globalThis.fetch;
}
export interface Application {
    id: string;
    name: string;
    slug: string;
    description: string | null;
    application_type: "web" | "spa" | "mobile" | "server" | "machine";
}
export interface TokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: "Bearer";
    expires_in: number;
}
export interface AuthForgeErrorBody {
    error?: {
        code?: string;
        message?: string;
        request_id?: string;
    };
}
export declare class AuthForgeError extends Error {
    readonly status: number;
    readonly code: string;
    readonly requestId?: string | undefined;
    constructor(status: number, code: string, message: string, requestId?: string | undefined);
}
export declare class AuthForge {
    private readonly options;
    private readonly requestFetch;
    constructor(options: AuthForgeOptions);
    private request;
    readonly service: {
        application: () => Promise<Application>;
    };
    readonly auth: {
        register: (email: string, password: string) => Promise<unknown>;
        login: (email: string, password: string) => Promise<TokenResponse>;
        refresh: (refreshToken: string) => Promise<TokenResponse>;
    };
}
