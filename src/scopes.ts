/**
 * @description
 * Defines the supported OAuth 2.1 scopes for the Authentication Server worker.
 * Maps scope names to user-friendly descriptions for display on consent screens
 * and for validation purposes.
 *
 * Key features:
 * - Central repository for scope definitions.
 * - Provides descriptions for the user consent UI.
 * - Includes helper functions for scope validation and retrieval.
 *
 * @notes
 * - Add, remove, or modify scopes based on the requirements of the resource servers
 *   that will consume the tokens issued by this auth server.
 * - Ensure scope names are concise and follow common conventions (e.g., resource:action).
 */

/**
 * Defines the structure for a single scope definition.
 */
export interface ScopeDefinition {
	/**
	 * A user-friendly description of the permission granted by this scope.
	 * This will be shown to the user on the consent screen.
	 */
	description: string;
	/**
	 * Optional: Indicates if this scope should be considered critical or requires
	 * special attention during the consent process.
	 */
	is_sensitive?: boolean;
	/**
	 * Optional: Indicates if this scope is granted by default without explicit user consent
	 * (use with caution, generally applicable only to very basic scopes like openid).
	 */
	is_default?: boolean;
}

/**
 * A record mapping supported scope names (strings) to their definitions.
 */
export const SUPPORTED_SCOPES: Record<string, ScopeDefinition> = {
	/**
	 * Standard OpenID Connect scope: Requests access to the user's unique identifier (sub claim).
	 */
	openid: {
		description: 'Authenticate your identity.',
        is_default: true, // Often considered a default scope
	},
	/**
	 * Standard OpenID Connect scope: Requests access to basic profile information
	 * (name, picture, etc.) associated with the authenticated user.
	 */
	profile: {
		description: "Access your basic profile information (e.g., name, user ID).",
	},
	/**
	 * Standard OpenID Connect scope: Requests access to the user's email address.
	 */
	email: {
		description: 'Access your email address.',
        is_sensitive: true, // Email is often considered sensitive PII
	},
	/**
	 * Custom scope: Allows the client to request a refresh token to obtain new
	 * access tokens without requiring the user to log in again.
	 */
	offline_access: {
		description: 'Access your data when you are not actively using the application.',
        is_sensitive: true, // Ability to maintain long-term access is sensitive
	},
    /**
     * Custom Scope: Example scope for reading data from the MCP Resource Server.
     */
    'mcp:data:read': {
        description: 'Read data from the MCP Resource Server.'
    },
    /**
     * Custom Scope: Example scope for writing data to the MCP Resource Server.
     */
    'mcp:data:write': {
        description: 'Write data to the MCP Resource Server.',
        is_sensitive: true,
    },
	// Add more custom scopes specific to your resource servers as needed.
	// Example: 'mcp:config:read', 'mcp:config:write'
};

/**
 * Gets the description for a given scope name.
 * @param scopeName The name of the scope.
 * @returns The description string or a default message if the scope is unknown/unsupported.
 */
export function getScopeDescription(scopeName: string): string {
	return SUPPORTED_SCOPES[scopeName]?.description || `Unknown permission: ${scopeName}`;
}

/**
 * Represents the information about a scope needed for UI display or processing.
 */
export interface ScopeInfo {
	name: string;
	description: string;
	is_sensitive?: boolean;
    is_default?: boolean;
}

/**
 * Filters a list of requested scopes against the supported scopes and returns
 * an array of valid ScopeInfo objects including their definitions.
 *
 * @param requestedScopes An array of scope names requested by the client. Can be null or undefined.
 * @returns An array of valid ScopeInfo objects for supported scopes. Returns an empty array if no valid scopes are found or requested.
 */
export function getValidScopeInfo(requestedScopes: string[] | null | undefined): ScopeInfo[] {
	if (!requestedScopes || requestedScopes.length === 0) {
		// Return default scopes if any, otherwise empty
        return Object.entries(SUPPORTED_SCOPES)
            .filter(([_, def]) => def.is_default)
            .map(([name, def]) => ({
                name: name,
                description: def.description,
                is_sensitive: def.is_sensitive,
                is_default: def.is_default,
            }));
	}

	return requestedScopes
		.filter(scopeName => SUPPORTED_SCOPES.hasOwnProperty(scopeName)) // Keep only supported scopes
		.map(scopeName => {
            const def = SUPPORTED_SCOPES[scopeName];
            // Add non-null assertion '!' because filter ensures def exists
            return {
                name: scopeName,
                description: def!.description,
                is_sensitive: def!.is_sensitive,
                is_default: def!.is_default,
            };
        });
}

/**
 * Checks if a given scope name is supported by this authorization server.
 * @param scopeName The scope name to check.
 * @returns True if the scope is supported, false otherwise.
 */
export function isScopeSupported(scopeName: string): boolean {
    return SUPPORTED_SCOPES.hasOwnProperty(scopeName);
}
