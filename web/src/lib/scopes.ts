import definitions from "../../../shared/oidc_scopes.json" with { type: "json" };

export type Scope = keyof typeof definitions;
export const OIDC_SCOPES = Object.keys(definitions) as Scope[];
export const OPTIONAL_SCOPES = OIDC_SCOPES.filter((scope): scope is Exclude<Scope, "openid"> => scope !== "openid");
export const scopeDescription = (scope: Scope) => definitions[scope];
