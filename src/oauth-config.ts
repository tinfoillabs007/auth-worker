/**
 * @description
 * Configuration constants for the OAuth 2.1 provider running in the worker.
 * Includes client registration details and potentially other settings.
 *
 * @dependencies
 * - @cloudflare/workers-oauth-provider: Provides the ClientInfo type.
 *
 * @notes
 * - Client secrets should NOT be hardcoded here for production. Use secrets management
 *   or dynamic client registration. This example uses a hardcoded public client for demo purposes.
 * - Redirect URIs must exactly match the URIs the client application will use.
 */

import type { ClientInfo } from '@cloudflare/workers-oauth-provider';

/**
 * Example client registration for the Next.js demo application.
 * In a real application, load clients dynamically from KV or a database.
 */
export const DEMO_CLIENT: ClientInfo = {
	/**
	 * The unique identifier for the client application.
	 * This must match the client_id used by the Next.js app.
	 */
	clientId: 'mcp-auth-demo-client', // Example Client ID

	/**
	 * The human-readable name of the client application.
	 * Displayed on the consent screen.
	 */
	clientName: 'MCP Auth Demo App',

	// clientSecret: 'YOUR_CLIENT_SECRET_IF_CONFIDENTIAL', // Omitted for public client example

	/**
	 * An array of allowed redirection URIs for this client.
	 * The authorization server will only redirect to these URIs after authorization.
	 * This MUST match the callback URL configured in the Next.js app.
	 */
	redirectUris: [
		'http://localhost:3000/client' // Default local Next.js callback path used in existing code
        // Add production callback URL here later: e.g., 'https://your-app.com/client'
    ],

	/**
	 * OAuth grant types allowed for this client.
	 * 'authorization_code' is standard for web apps.
	 * 'refresh_token' allows the client to obtain new access tokens without user interaction.
	 */
	grantTypes: ['authorization_code', 'refresh_token'],

    /**
     * OAuth response types allowed for this client.
     * 'code' corresponds to the Authorization Code Grant.
     */
    responseTypes: ['code'],

    /**
     * Default scopes assigned or allowed for this client if none are requested.
     * Optional - scopes requested during authorization take precedence.
     */
    // scope: ['profile:read'], // Example default scope

    /**
     * Optional: URL for the client's logo, displayed on the consent screen.
     */
    // logoUri: 'https://your-app.com/logo.png',

    /**
     * Optional: URL of the client application's home page.
     */
    // clientUri: 'https://your-app.com',

    /**
     * Optional: Token endpoint authentication method.
     * 'none' is typical for public clients (using PKCE).
     * 'client_secret_basic' or 'client_secret_post' for confidential clients.
     */
    tokenEndpointAuthMethod: 'none', // Explicitly setting 'none' for public client with PKCE
};

/**
 * Array containing all registered clients.
 * In a real scenario, this would be replaced by logic to fetch clients from storage (like KV).
 */
export const REGISTERED_CLIENTS: ClientInfo[] = [
	DEMO_CLIENT,
	{
		clientId: '4VNyg7t0q1UprzRo', // Must match HELPER_APP_CLIENT_ID in .env
		clientName: 'Local Agent Helper',
		redirectUris: ['http://localhost:8990/callback'],
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		tokenEndpointAuthMethod: 'none'
	}
];

// --- Other OAuth Configurations ---

/**
 * Default lifetime for authorization codes in seconds.
 */
export const AUTH_CODE_LIFETIME_SECONDS = 60; // 1 minute

/**
 * Default lifetime for access tokens in seconds.
 */
export const ACCESS_TOKEN_LIFETIME_SECONDS = 3600; // 1 hour

/**
 * Default lifetime for refresh tokens in seconds.
 * Typically much longer than access tokens.
 */
export const REFRESH_TOKEN_LIFETIME_SECONDS = 2592000; // 30 days
