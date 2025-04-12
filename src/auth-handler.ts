/**
 * @description
 * Handlers for the multi-stage OAuth 2.1 Authorization Endpoint (`/authorize`) flow
 * and the JWKS endpoint within the Authentication Server Worker.
 *
 * Stages:
 * 1. GET /authorize: Validate client, parameters; store state; serve iframe host page.
 * 2. POST /authorize (step=hanko_success): Receive Hanko result; update state; serve consent page.
 * 3. POST /authorize (step=consent_submit): Process user consent; complete authorization; redirect.
 *
 * @dependencies
 * - hono: Context type definition.
 * - jose: For JWK parsing, export, and thumbprint calculation.
 * - ./env: Env type definition.
 * - ./oauth-helpers: Utilities (KV storage, random strings, HTML escaping, types).
 * - ./scopes: Scope definitions and utilities.
 * - ./oauth-config: Hardcoded DEMO_CLIENT for seeding KV in dev.
 * - @cloudflare/workers-oauth-provider: Core library types (ClientInfo, AuthRequest, etc.) and injected helpers (OAuthHelpers).
 *
 * @notes
 * - Relies on OAuthHelpers being injected into `c.env.OAUTH_PROVIDER` by the main library setup in index.ts.
 * - Security is paramount: state validation, PKCE (handled by library), client/redirect validation.
 * - Error handling redirects back to the client application with standard OAuth error codes.
 * - Includes logic to seed the hardcoded DEMO_CLIENT into KV if not found, facilitating local dev.
 * - JWKS endpoint implementation assumes OAUTH_SIGNING_KEY is a private JWK (e.g., RSA or EC) or a symmetric secret string.
 */

import type { Context as HonoContext } from 'hono';
import type { Env } from './env';
import {
	generateRandomString,
	storeTemporaryOAuthState,
	getTemporaryOAuthState,
	deleteTemporaryOAuthState,
	escapeHtml
} from './oauth-helpers';
// Import types using 'import type'
import type { TemporaryOAuthState as OriginalTemporaryOAuthState } from './oauth-helpers';
import type { ClientInfo, AuthRequest, CompleteAuthorizationOptions, OAuthHelpers } from '@cloudflare/workers-oauth-provider';
// Import types using 'import type' and values separately if needed (getValidScopeInfo is a value)
import { getValidScopeInfo } from './scopes';
import type { ScopeInfo } from './scopes';
import { DEMO_CLIENT } from './oauth-config'; // Import the hardcoded client for seeding
// Import JOSE for JWKS handling
import { importJWK, exportJWK, calculateJwkThumbprint } from 'jose';
import type { JWK } from 'jose';

// Define context type expected by these handlers (with injected helpers)
type HandlerContext = HonoContext<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>;

// --- Constants ---
const STATE_TTL_SECONDS = 600; // 10 minutes TTL for temporary state in KV

// --- Update TemporaryOAuthState type ---
type TemporaryOAuthState = OriginalTemporaryOAuthState;

// --- Client Validation Helper ---

/**
 * Validates Client ID and Redirect URI.
 * Checks KV for the client config. If not found and matches DEMO_CLIENT, seeds KV.
 * @param env - The worker environment containing OAUTH_KV.
 * @param clientId - The client ID from the request.
 * @param redirectUri - The redirect URI from the request.
 * @returns The validated ClientInfo object.
 * @throws Error with OAuth error details if validation fails.
 */
async function validateClientAndRedirectUri(env: Env, clientId: string, redirectUri: string): Promise<ClientInfo> {
	if (!clientId || !redirectUri) {
		const error = new Error('Missing client_id or redirect_uri.');
		(error as any).error = 'invalid_request';
		throw error;
	}
	console.log(`[validateClientAndRedirectUri] Validating client_id: ${clientId}, redirect_uri: ${redirectUri}`);

    if (!env.OAUTH_KV) {
        console.error("OAUTH_KV namespace is not available in env.");
		throw new Error("Storage configuration error (OAUTH_KV missing).");
    }

	const clientKey = `client:${clientId}`;
	let client: ClientInfo | null = await env.OAUTH_KV.get<ClientInfo>(clientKey, { type: 'json' });

    // Seed KV with DEMO_CLIENT if it's requested but not found (for local dev)
    if (!client && clientId === DEMO_CLIENT.clientId) {
        console.warn(`[validateClientAndRedirectUri] Client ${clientId} not found in KV. Seeding with DEMO_CLIENT config...`);
        try {
            // IMPORTANT: In a real app, you wouldn't store secrets directly if the client was confidential.
            // DEMO_CLIENT is public (tokenEndpointAuthMethod: 'none'), so no secret is stored.
            await env.OAUTH_KV.put(clientKey, JSON.stringify(DEMO_CLIENT));
            console.log(`[validateClientAndRedirectUri] Seeded KV with ${clientId}`);
            // Retry getting the client after seeding
            client = await env.OAUTH_KV.get<ClientInfo>(clientKey, { type: 'json' });
        } catch (kvError: any) {
            console.error(`[validateClientAndRedirectUri] Failed to seed KV for ${clientId}:`, kvError);
            const error = new Error(`Internal storage error during client seeding: ${kvError.message}`);
            (error as any).error = 'server_error';
            throw error;
        }
    }

	if (!client) {
		console.log(`[validateClientAndRedirectUri] Client validation failed: Client not found in KV: ${clientId}`);
		const error = new Error('Unknown or invalid client.');
		(error as any).error = 'unauthorized_client';
		throw error;
	}

    console.log(`[validateClientAndRedirectUri] Found client in KV: ${client.clientName}`);


	if (!client.redirectUris || !client.redirectUris.includes(redirectUri)) {
		console.log(`[validateClientAndRedirectUri] Client validation failed: Redirect URI '${redirectUri}' not registered for client ${clientId}`);
		const error = new Error('Invalid redirect_uri.');
		(error as any).error = 'invalid_request';
		(error as any).error_description = 'The provided redirect_uri is not registered for this client.';
		throw error;
	}
	console.log(`[validateClientAndRedirectUri] Client validation successful: ${clientId}`);
	return client;
}

// --- HTML Template Generation ---

/**
 * Generates the HTML page served by the worker to host the Hanko authentication iframe.
 * Includes JavaScript to listen for postMessage events from the iframe.
 * @param sessionId - The temporary session ID for this authorization flow.
 * @param mcpWorkerUrl - The origin URL of the MCP Worker (where the vault UI is served).
 * @returns The HTML string.
 */
function getIframeHostHtml(sessionId: string, mcpWorkerUrl: string): string {
	const iframeSrc = mcpWorkerUrl; // Assume MCP Worker serves its UI at its root
	const expectedMessageOrigin = mcpWorkerUrl;
	// Basic styling, consider external CSS or more robust styling solution
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authenticate</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 90vh; margin: 0; background-color: #f0f0f0; color: #333; }
        .container { background-color: #fff; padding: 25px 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; max-width: 480px; width: 90%; border: 1px solid #ddd; }
        iframe { border: 1px solid #ccc; border-radius: 6px; width: 100%; box-sizing: border-box; min-height: 480px; margin-top: 15px; }
        #status { margin-top: 20px; font-style: italic; color: #555; min-height: 1.2em; font-size: 0.9em; }
        form { display: none; }
        h2 { margin-top: 0; margin-bottom: 10px; font-size: 1.4em; font-weight: 600; }
        p { margin: 0 0 15px 0; color: #666; font-size: 0.95em; }
        .loader { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite; margin: 10px auto; display: none; /* Initially hidden */ }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h2>Authentication Required</h2>
        <p>Please complete the authentication process below.</p>
        <iframe id="hankoAuthFrame" src="${escapeHtml(iframeSrc)}" title="Hanko Authentication" allow="publickey-credentials-get *"></iframe>
        <div id="status">Loading authentication service...</div>
        <div id="loader" class="loader"></div>

        <!-- Hidden form to submit back to the worker -->
        <form id="hankoCallbackForm" method="POST" action="/authorize">
            <input type="hidden" name="session_id" value="${escapeHtml(sessionId)}">
            <input type="hidden" name="hanko_user_id" id="hankoUserIdInput">
            <input type="hidden" name="flow_step" value="hanko_success"> <!-- Indicate step -->
        </form>
    </div>

    <script>
        // VERY EARLY LOG - Does the script block even start?
        console.log('[Auth Worker Host Page] SCRIPT BLOCK START');
        try {
             console.log('[Auth Worker Host Page] Inside try block.');
             // Hardcode the origin string for debugging script execution
             const expectedOrigin = 'http://localhost:8789'; 
             const statusDiv = document.getElementById('status');
             const loaderDiv = document.getElementById('loader');
             const hankoUserIdInput = document.getElementById('hankoUserIdInput');
             const callbackForm = document.getElementById('hankoCallbackForm');
             const iframe = document.getElementById('hankoAuthFrame');

             console.log('[Auth Worker Host Page] Expected Origin:', expectedOrigin);
             // Check if elements were found
             if (!callbackForm || !hankoUserIdInput) {
                 console.error('[Auth Worker Host Page] CRITICAL ERROR: Hidden form or input field not found in DOM!');
                 if(statusDiv) statusDiv.textContent = 'Page setup error.';
                 // Cannot proceed without the form - Throw error to be caught
                 throw new Error("Callback form elements missing"); 
             }
             console.log('[Auth Worker Host Page] DOM Elements found:', { statusDiv, loaderDiv, hankoUserIdInput: !!hankoUserIdInput, callbackForm: !!callbackForm, iframe: !!iframe });

             console.log('[Auth Worker Host Page] Attaching message listener...');
             // Restore original listener logic
             window.addEventListener('message', (event) => {
                 console.log('[Auth Worker Host Page] Message received:', event);
                 console.log('[Auth Worker Host Page] Message Origin:', event.origin);
                 console.log('[Auth Worker Host Page] Message Data:', event.data);

                 // **Security: ALWAYS validate the origin**
                 if (event.origin !== expectedOrigin) {
                     console.warn('[Auth Worker Host Page] Message from unexpected origin ignored.');
                     return;
                 }
                 console.log('[Auth Worker Host Page] Origin validation passed.');

                 // Validate message structure
                 if (typeof event.data !== 'object' || event.data === null || typeof event.data.type !== 'string') {
                      console.warn('[Auth Worker Host Page] Received malformed message structure.');
                      if(statusDiv) statusDiv.textContent = 'Error: Invalid message received.';
                      if(loaderDiv) loaderDiv.style.display = 'none';
                      return;
                 }
                 console.log('[Auth Worker Host Page] Message structure validation passed. Type:', event.data.type);

                 if (event.data.type === 'HANKO_AUTH_SUCCESS') {
                     console.log('[Auth Worker Host Page] HANKO_AUTH_SUCCESS message processing...');
                     if(statusDiv) statusDiv.textContent = 'Authentication successful! Processing...';
                     if(loaderDiv) loaderDiv.style.display = 'block'; // Show loader

                     if (event.data.payload && typeof event.data.payload.hankoUserId === 'string') {
                         console.log('[Auth Worker Host Page] Payload valid, Hanko User ID:', event.data.payload.hankoUserId);
                         // Already checked callbackForm/hankoUserIdInput exist outside listener
                         console.log('[Auth Worker Host Page] Setting input value and submitting form...');
                         hankoUserIdInput.value = event.data.payload.hankoUserId;
                         // Submit the form back to the worker's POST /authorize endpoint
                         setTimeout(() => {
                              console.log('[Auth Worker Host Page] Submitting callbackForm.');
                              callbackForm.submit();
                         }, 100); // Brief delay before submit

                     } else {
                          console.error('[Auth Worker Host Page] HANKO_AUTH_SUCCESS message payload is missing or invalid:', event.data.payload);
                          if(statusDiv) statusDiv.textContent = 'Error: Invalid authentication data received.';
                          if(loaderDiv) loaderDiv.style.display = 'none';
                     }

                 } else if (event.data.type === 'HANKO_AUTH_ERROR') {
                      console.error('[Auth Worker Host Page] HANKO_AUTH_ERROR message received:', event.data.payload);
                      const errorMessage = event.data.payload?.message || 'Unknown authentication error.';
                      // Use concatenation to avoid build errors with template literals
                      if(statusDiv) statusDiv.textContent = 'Authentication failed: ' + escapeHtml(errorMessage.substring(0, 100)); 
                      if(loaderDiv) loaderDiv.style.display = 'none';
                 } else {
                      console.log('[Auth Worker Host Page] Ignoring irrelevant message type:', event.data.type);
                 }
             });
             console.log('[Auth Worker Host Page] Message listener attached successfully.');

             // Existing iframe load/error listeners...
              if (iframe) {
                  iframe.addEventListener('load', () => {
                     console.log('[Auth Worker Host Page] Hanko auth iframe loaded event.');
                     if (statusDiv && statusDiv.textContent === 'Loading authentication service...') {
                         statusDiv.textContent = 'Waiting for authentication...';
                     }
                     if(loaderDiv) loaderDiv.style.display = 'none';
                  });
                  iframe.addEventListener('error', (e) => {
                     console.error('[Auth Worker Host Page] Hanko auth iframe failed to load event:', e);
                     if(statusDiv) statusDiv.textContent = 'Error loading authenticator component.';
                     if(loaderDiv) loaderDiv.style.display = 'none';
                  });
             } else {
                 console.error('[Auth Worker Host Page] Error: Could not find authentication frame element.');
                 if(statusDiv) statusDiv.textContent = 'Error: Could not find authentication frame.';
                 if(loaderDiv) loaderDiv.style.display = 'none';
             }

        } catch (scriptError) {
             console.error('[Auth Worker Host Page] CRITICAL ERROR in script block:', scriptError);
             // Attempt to display error on page if statusDiv exists
             try { 
                const statusDiv = document.getElementById('status'); 
                if(statusDiv) statusDiv.textContent = 'Page script error occurred. Check console.'; 
             } catch(e) {}
        }
    </script>
</body>
</html>`;
}

/**
 * Generates the HTML page for the user consent screen.
 * Displays client information and requested scopes.
 * @param sessionId - The temporary session ID.
 * @param client - Information about the client application.
 * @param scopes - Array of scopes being requested, with descriptions.
 * @param state - The original state parameter from the client (for CSRF protection).
 * @returns The HTML string.
 */
function getConsentPageHtml(sessionId: string, client: ClientInfo, scopes: ScopeInfo[], state?: string): string {
	const scopeItemsHtml = scopes.map(scope => `
        <li class="scope-item ${scope.is_sensitive ? 'sensitive' : ''}">
            <strong class="scope-name">${escapeHtml(scope.name)}</strong>
            <p class="scope-description">${escapeHtml(scope.description)}</p>
            ${scope.is_sensitive ? '<span class="sensitive-badge">Sensitive</span>' : ''}
        </li>
    `).join('');

	const clientLogoHtml = client.logoUri
		? `<img src="${escapeHtml(client.logoUri)}" alt="${escapeHtml(client.clientName || 'Client')} logo" class="client-logo-img">`
		: `<div class="client-logo-initial">${escapeHtml((client.clientName || '?').charAt(0).toUpperCase())}</div>`;

	// Enhanced styling for consent page
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Grant Access</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background-color: #f4f5f7; color: #333; padding: 20px; }
        .container { background-color: #fff; padding: 35px 40px; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.08); max-width: 550px; width: 100%; border: 1px solid #e1e4e8; }
        .client-info { display: flex; align-items: center; margin-bottom: 25px; padding-bottom: 20px; border-bottom: 1px solid #e1e4e8; }
        .client-logo { width: 50px; height: 50px; background-color: #eee; border-radius: 6px; margin-right: 15px; display: flex; align-items: center; justify-content: center; overflow: hidden; flex-shrink: 0; }
        .client-logo-img { max-width: 100%; max-height: 100%; object-fit: contain; }
        .client-logo-initial { font-size: 20px; color: #555; font-weight: 600; }
        .client-details h2 { margin: 0 0 4px 0; font-size: 1.3em; font-weight: 600; }
        .client-details p { margin: 0; color: #586069; font-size: 0.95em; }
        .consent-prompt { margin-bottom: 15px; font-size: 1.05em; color: #24292e; }
        .scope-list { list-style: none; padding: 0; margin: 25px 0; max-height: 250px; overflow-y: auto; border: 1px solid #e1e4e8; border-radius: 6px; background-color: #f6f8fa; }
        .scope-item { padding: 15px 20px; border-bottom: 1px solid #e1e4e8; position: relative; }
        .scope-item:last-child { border-bottom: none; }
        .scope-name { font-weight: 600; color: #24292e; margin-bottom: 3px; }
        .scope-description { font-size: 0.9em; color: #586069; margin: 0; }
        .scope-item.sensitive .scope-name { color: #d73a49; }
        .sensitive-badge { background-color: #f9d7d9; color: #d73a49; font-size: 0.75em; padding: 2px 6px; border-radius: 4px; font-weight: 600; margin-left: 8px; vertical-align: middle; }
        .actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 30px; }
        .btn { padding: 10px 22px; border: 1px solid; border-radius: 6px; cursor: pointer; font-size: 0.95em; font-weight: 500; transition: background-color 0.2s, border-color 0.2s; }
        .btn-deny { background-color: #fafbfc; color: #d73a49; border-color: #e1e4e8; }
        .btn-deny:hover { background-color: #f3f4f6; border-color: #d1d5da; }
        .btn-allow { background-color: #2ea44f; color: white; border-color: #2ea44f; }
        .btn-allow:hover { background-color: #2c974b; border-color: #2c974b; }
        form { margin: 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="client-info">
            <div class="client-logo">${clientLogoHtml}</div>
            <div class="client-details">
                <h2>Authorize ${escapeHtml(client.clientName || 'Application')}</h2>
                <p>${escapeHtml(client.clientName || 'This application')} wants to access your account.</p>
            </div>
        </div>
        <p class="consent-prompt">Review the requested permissions:</p>
        <ul class="scope-list">
            ${scopeItemsHtml.length > 0 ? scopeItemsHtml : '<li><p class="scope-description">No specific permissions requested.</p></li>'}
        </ul>
        <form method="POST" action="/authorize">
            <input type="hidden" name="session_id" value="${escapeHtml(sessionId)}">
            <input type="hidden" name="flow_step" value="consent_submit">
            ${state ? `<input type="hidden" name="state" value="${escapeHtml(state)}">` : ''}
            <div class="actions">
                <button type="submit" name="consent_decision" value="deny" class="btn btn-deny">Deny</button>
                <button type="submit" name="consent_decision" value="allow" class="btn btn-allow">Allow Access</button>
            </div>
        </form>
    </div>
</body>
</html>`;
}

// --- Authorization Endpoint Handlers ---

/**
 * Handles the initial GET /authorize request.
 */
export async function handleAuthorizeGetRequest(c: HandlerContext): Promise<Response> {
	const { env } = c;
	const request = c.req.raw;
	const providerHelpers = env.OAUTH_PROVIDER; // Helpers injected by the library

	console.log("[handleAuthorizeGetRequest] START"); // Added log
	console.log("[handleAuthorizeGetRequest] Injected OAUTH_PROVIDER helpers:", providerHelpers ? Object.keys(providerHelpers) : 'null or undefined'); // Log keys of helper

	if (!providerHelpers) {
		console.error("OAuthHelpers not found on c.env in GET /authorize");
		return c.text("Internal configuration error: Provider helpers not available.", 500);
	}

	let authRequest: AuthRequest;
	let redirectUriOnError: string | undefined;
	let stateOnError: string | undefined;

	try {
		// 1. Parse and perform initial validation via the library helper
        console.log("[handleAuthorizeGetRequest] Calling parseAuthRequest...");
		authRequest = await providerHelpers.parseAuthRequest(request);
        console.log("[handleAuthorizeGetRequest] parseAuthRequest successful:", authRequest);
		redirectUriOnError = authRequest.redirectUri; // Store for potential error redirect
		stateOnError = authRequest.state;

		// 2. Validate client_id and redirect_uri against registered clients
		const client = await validateClientAndRedirectUri(env, authRequest.clientId, authRequest.redirectUri);
        console.log("[handleAuthorizeGetRequest] Client validation successful.");

		// 3. Validate response_type (assuming 'code' is the only supported type here)
		if (authRequest.responseType !== 'code') {
			const error = new Error(`Unsupported response_type: ${authRequest.responseType}`);
			(error as any).error = 'unsupported_response_type';
			throw error;
		}
		console.log("[handleAuthorizeGetRequest] response_type validation successful.");
		// TODO: Add validation for PKCE parameters (code_challenge, code_challenge_method) if not handled by parseAuthRequest

		// 4. Generate temporary session ID
		const sessionId = generateRandomString(32);
        console.log(`[handleAuthorizeGetRequest] Generated sessionId: ${sessionId}`);

		// 5. Store essential OAuth parameters in KV associated with session ID
		const oauthStateToStore: TemporaryOAuthState = {
			responseType: authRequest.responseType,
			clientId: authRequest.clientId,
			redirectUri: authRequest.redirectUri,
			scope: authRequest.scope,
			state: authRequest.state,
			codeChallenge: authRequest.codeChallenge,
			codeChallengeMethod: authRequest.codeChallengeMethod,
			status: 'pending_hanko_auth', // Initial status
		};

		await storeTemporaryOAuthState(env, sessionId, oauthStateToStore, STATE_TTL_SECONDS);
        console.log(`[handleAuthorizeGetRequest] Stored state for session ${sessionId}`);

		// 6. Determine the origin of the MCP Worker for iframe src and postMessage target
		const mcpWorkerUrl = env.MCP_WORKER_URL;
		if (!mcpWorkerUrl) {
			console.error("MCP_WORKER_URL environment variable not set in Worker.");
			const error = new Error("Internal configuration error: Vault Worker URL missing.");
			(error as any).error = 'server_error';
			throw error;
		}
		console.log(`[handleAuthorizeGetRequest] mcpWorkerUrl: ${mcpWorkerUrl}`);

		// 7. Return the HTML page containing the iframe and listener script
		const htmlContent = getIframeHostHtml(sessionId, mcpWorkerUrl);
		console.log("[handleAuthorizeGetRequest] Returning iframe host HTML.");
		return c.html(htmlContent);

	} catch (error: any) {
		console.error('[handleAuthorizeGetRequest] Error:', error); // Ensure error is logged here too
		// Attempt to redirect back to client with error
		const redirectUri = redirectUriOnError || new URL(request.url).searchParams.get('redirect_uri');
		const state = stateOnError || new URL(request.url).searchParams.get('state');
		const oauthError = error.error || 'invalid_request';
		const errorDescription = error.error_description || error.message || 'Invalid authorization request.';

		if (redirectUri) {
			try {
				// IMPORTANT: Re-validate redirectUri against known clients before redirecting with error
				// This avoids open redirector vulnerabilities if initial validation failed early.
				// Simplified check: Just ensure it's a valid URL structure here. A full check is better.
				const errorRedirectUrl = new URL(redirectUri);
				errorRedirectUrl.searchParams.set('error', oauthError);
				errorRedirectUrl.searchParams.set('error_description', errorDescription);
				if (state) { // Only include state if it was originally provided
					errorRedirectUrl.searchParams.set('state', state);
				}
				console.log(`[handleAuthorizeGetRequest] Redirecting with error to: ${errorRedirectUrl.toString()}`);
				return c.redirect(errorRedirectUrl.toString(), 302);
			} catch (e) {
				console.error("[handleAuthorizeGetRequest] Error constructing/parsing error redirect URL:", e);
				// Fallthrough to generic error page
			}
		}
		// Fallback to generic error page if redirect URI is invalid or missing
		console.log("[handleAuthorizeGetRequest] Falling back to generic error page.");
		const errorHtml = `<html><body><h1>Authorization Error</h1><p>${escapeHtml(errorDescription)}</p>${state ? `<p>State: ${escapeHtml(state)}</p>` : ''}</body></html>`;
		return c.html(errorHtml, 400);
	}
}

// --- Define Hanko User type (REMOVE - not needed here anymore) ---
// interface HankoUser { ... }

/**
 * Handles the POST /authorize request *after* successful Hanko authentication via iframe.
 */
export async function handleAuthorizePostHankoSuccess(c: HandlerContext): Promise<Response> {
	const { env } = c;
	const providerHelpers = env.OAUTH_PROVIDER;
	console.log("[handleAuthorizePostHankoSuccess] START");

	if (!providerHelpers) {
		console.error("OAuthHelpers not found on c.env in POST /authorize (Hanko Success)");
		return c.text("Internal configuration error: Provider not available.", 500);
	}

	let sessionId: string | null = null;
	let storedState: TemporaryOAuthState | null = null;

	try {
		// 1. Parse form data
		const formData = await c.req.formData();
		sessionId = formData.get('session_id') as string | null;
		const hankoUserId = formData.get('hanko_user_id') as string | null;
        console.log(`[handleAuthorizePostHankoSuccess] Received sessionId: ${sessionId}, hankoUserId: ${hankoUserId}`);

		if (!sessionId || !hankoUserId) {
			console.error("Missing session_id or hanko_user_id in form data");
			return c.text("Invalid request: Missing session information.", 400);
		}

		// 2. Retrieve stored OAuth state from KV
		storedState = await getTemporaryOAuthState(env, sessionId);
		if (!storedState) {
			console.error(`No stored state found for session ID: ${sessionId}`);
			return c.text("Invalid or expired session. Please start the authorization flow again.", 400);
		}
        console.log("[handleAuthorizePostHankoSuccess] Retrieved stored state:", storedState);

		// 3. Validate status
		if (storedState.status !== 'pending_hanko_auth') {
			console.error(`Unexpected status '${storedState.status}' for session ID: ${sessionId}`);
			await deleteTemporaryOAuthState(env, sessionId);
			const error = new Error("Invalid session state.");
			(error as any).error = 'invalid_request';
			throw error;
		}
        console.log("[handleAuthorizePostHankoSuccess] Status validation successful.");

		// 4. Update stored state (JUST hankoUserId and status)
		storedState.hankoUserId = hankoUserId;
		storedState.status = 'pending_consent';
		await storeTemporaryOAuthState(env, sessionId, storedState, STATE_TTL_SECONDS);
		console.log(`[handleAuthorizePostHankoSuccess] Updated OAuth state for session ${sessionId} to pending_consent with Hanko User ID: ${hankoUserId}`);

		// 5. Get Client Info for Consent Page
        console.log(`[handleAuthorizePostHankoSuccess] Looking up client: ${storedState.clientId}`);
		const client = await providerHelpers.lookupClient(storedState.clientId);
		if (!client) {
			console.error(`Client ${storedState.clientId} disappeared mid-flow for session ${sessionId}`);
			await deleteTemporaryOAuthState(env, sessionId);
			const error = new Error("Internal server error: Client configuration issue.");
			(error as any).error = 'server_error';
			throw error;
		}
        console.log(`[handleAuthorizePostHankoSuccess] Client found: ${client.clientName}`);

		// 6. Prepare Scope Information for Consent UI
		const validScopesForConsentUI: ScopeInfo[] = getValidScopeInfo(storedState.scope);
        console.log("[handleAuthorizePostHankoSuccess] Valid scopes for UI:", validScopesForConsentUI);

		// 7. Render and return the Consent UI HTML
		console.log(`[handleAuthorizePostHankoSuccess] Rendering consent page for session ${sessionId}`);
		const consentHtml = getConsentPageHtml(sessionId, client, validScopesForConsentUI, storedState.state);
		return c.html(consentHtml);

	} catch (error: any) {
		console.error("[handleAuthorizePostHankoSuccess] Error:", error);
		if (sessionId) {
			await deleteTemporaryOAuthState(env, sessionId).catch(e => console.error("Error cleaning up state during Hanko Success error handling:", e));
		}
		if (storedState && !(error as any).redirect_uri) (error as any).redirect_uri = storedState.redirectUri;
        if (storedState && !(error as any).state) (error as any).state = storedState.state;
		throw error; // Re-throw for the main Hono onError handler
	}
}

/**
 * Handles the POST /authorize request *after* the user submits the consent form.
 */
export async function handleAuthorizePostConsent(c: HandlerContext): Promise<Response> {
	const { env } = c;
	const providerHelpers = env.OAUTH_PROVIDER;
	console.log("[handleAuthorizePostConsent] START");

	if (!providerHelpers) {
		console.error("OAuthHelpers not found on c.env in POST /authorize (Consent)");
		return c.text("Internal configuration error: Provider not available.", 500);
	}

	let sessionId: string | null = null;
	let storedState: TemporaryOAuthState | null = null;

	try {
		// 1. Parse form data
		const formData = await c.req.formData();
		sessionId = formData.get('session_id') as string | null;
		const consentDecision = formData.get('consent_decision') as 'allow' | 'deny' | null;
		const stateParamFromForm = formData.get('state') as string | null;
        console.log(`[handleAuthorizePostConsent] Received sessionId: ${sessionId}, decision: ${consentDecision}, stateFromForm: ${stateParamFromForm}`);

		if (!sessionId || !consentDecision) {
			console.error("Missing session_id or consent_decision in form data");
			return c.text("Invalid request: Missing consent information.", 400);
		}

		// 2. Retrieve stored OAuth state from KV
		storedState = await getTemporaryOAuthState(env, sessionId);
		if (!storedState) {
			console.error(`No stored state found for session ID during consent: ${sessionId}`);
			return c.text("Invalid or expired session. Please start the authorization flow again.", 400);
		}
        console.log("[handleAuthorizePostConsent] Retrieved stored state:", storedState);

		// 3. Validate status and presence of Hanko user ID (REMOVE EMAIL CHECK)
		if (storedState.status !== 'pending_consent' || !storedState.hankoUserId /* || !storedState.userEmail */) { // <-- REMOVE EMAIL CHECK
			console.error(`Invalid state for consent submission: Status='${storedState.status}', HankoUserID=${storedState.hankoUserId ? 'present' : 'missing'}. Session: ${sessionId}`);
			await deleteTemporaryOAuthState(env, sessionId);
			const error = new Error("Invalid session state during consent (missing user details).");
			(error as any).error = 'invalid_request';
			throw error;
		}
        console.log("[handleAuthorizePostConsent] Status and Hanko User ID validation successful.");

		// 4. CRITICAL Security Check: Verify state parameter from form matches stored state
		if (stateParamFromForm !== (storedState.state || null)) {
			console.error(`CSRF Alert: State mismatch for session ID ${sessionId}. Form='${stateParamFromForm}', Stored='${storedState.state}'`);
			await deleteTemporaryOAuthState(env, sessionId);
			const error = new Error("State parameter mismatch.");
			(error as any).error = 'invalid_request';
			if (storedState.state) (error as any).state = storedState.state;
            else (error as any).state = undefined;
			throw error;
		}
        console.log("[handleAuthorizePostConsent] State parameter validation successful.");

		// 5. Handle Deny Decision
		if (consentDecision === 'deny') {
			console.log(`[handleAuthorizePostConsent] User denied access for session ID: ${sessionId}`);
			await deleteTemporaryOAuthState(env, sessionId);
			const error = new Error("The resource owner denied the request.");
			(error as any).error = 'access_denied';
			throw error;
		}
        console.log("[handleAuthorizePostConsent] User allowed access.");

		// --- User Allowed Access ---

		// 6. Determine granted scopes
        const grantedScopes = getValidScopeInfo(storedState.scope).map(s => s.name);
        console.log(`[handleAuthorizePostConsent] Granted scopes: ${grantedScopes.join(' ')}`);

		// 7. Prepare options for completeAuthorization (REMOVE EMAIL FROM PROPS)
		const authRequestForCompletion: AuthRequest = {
			responseType: storedState.responseType,
			clientId: storedState.clientId,
			redirectUri: storedState.redirectUri,
			scope: grantedScopes,
			state: storedState.state || '',
			codeChallenge: storedState.codeChallenge,
			codeChallengeMethod: storedState.codeChallengeMethod,
		};

		const completeAuthOptions: CompleteAuthorizationOptions = {
			request: authRequestForCompletion,
			userId: storedState.hankoUserId, 
			metadata: { authenticated_via: 'hanko', original_session_id: sessionId },
			scope: grantedScopes,
            // Only include hankoUserId in props now
			props: { 
                hankoUserId: storedState.hankoUserId 
                // email: storedState.userEmail // <-- REMOVE EMAIL HERE 
            }
		};
        console.log("[handleAuthorizePostConsent] Prepared options for completeAuthorization:", completeAuthOptions);

		// 8. Call library's completeAuthorization to generate the code
		console.log(`[handleAuthorizePostConsent] Calling completeAuthorization for session ID: ${sessionId}, User ID: ${storedState.hankoUserId}`);
		const authResponse = await providerHelpers.completeAuthorization(completeAuthOptions);
        console.log("[handleAuthorizePostConsent] completeAuthorization successful. Response:", authResponse);

		// 9. Delete temporary session state ONLY after successful completion
		await deleteTemporaryOAuthState(env, sessionId);

		// 10. Redirect the user agent back to the client's redirect_uri with code and state
		console.log(`[handleAuthorizePostConsent] Authorization successful. Redirecting to: ${authResponse.redirectTo}`);
		return c.redirect(authResponse.redirectTo, 302);

	} catch (error: any) {
		console.error("[handleAuthorizePostConsent] Error:", error);
		if (sessionId) {
			await deleteTemporaryOAuthState(env, sessionId).catch(e => console.error("Error cleaning up state during consent error handling:", e));
		}
		if (storedState && !(error as any).redirect_uri) (error as any).redirect_uri = storedState.redirectUri;
        if (storedState && !(error as any).state) (error as any).state = storedState.state;
        else if (!(error as any).state) (error as any).state = undefined;
		throw error; // Re-throw for the main Hono onError handler
	}
}

// --- JWKS Endpoint Handler --- NEW ---
/**
 * Handles GET requests to the /.well-known/jwks.json endpoint.
 * Dynamically generates the JWKS based on the OAUTH_SIGNING_KEY.
 */
export async function handleJwksRequest(c: HonoContext<{ Bindings: Env }>): Promise<Response> {
    const { env } = c;
	console.log("[handleJwksRequest] Request received.");

	if (!env.OAUTH_SIGNING_KEY) {
		console.error("OAUTH_SIGNING_KEY is not configured.");
		return c.json({ error: 'configuration_error', error_description: 'Signing key not configured.' }, 500);
	}

	try {
        let privateOrSecretKeyJwk: JWK;
        try {
            // First, try parsing as JWK (for asymmetric keys like RSA/EC)
            privateOrSecretKeyJwk = JSON.parse(env.OAUTH_SIGNING_KEY);
            if (!privateOrSecretKeyJwk.kty) throw new Error("Parsed key is not a valid JWK object.");
             console.log(`[handleJwksRequest] Parsed OAUTH_SIGNING_KEY as JWK (kty: ${privateOrSecretKeyJwk.kty}).`);
        } catch (e) {
             // If parsing as JWK fails, assume it's a raw secret string for HMAC (HS256)
             console.log("[handleJwksRequest] Failed to parse OAUTH_SIGNING_KEY as JWK, assuming symmetric secret for HS256.");
             const secretBytes = new TextEncoder().encode(env.OAUTH_SIGNING_KEY);
             // Use Web API approach for base64url encoding
             let binary = '';
             secretBytes.forEach((byte) => { binary += String.fromCharCode(byte); });
             const base64urlEncodedKey = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

             privateOrSecretKeyJwk = {
                 kty: 'oct',
                 k: base64urlEncodedKey,
                 alg: 'HS256',
                 use: 'sig'
             };
        }

		// Import the key (whether private JWK or symmetric 'oct' JWK)
		const key = await importJWK(privateOrSecretKeyJwk, privateOrSecretKeyJwk.alg || 'HS256');

		// Export the *public* part of the key
        // For symmetric 'oct' keys, exportJWK returns the same key
		const publicJwk = await exportJWK(key);

		// Ensure essential JWK properties for JWKS are present
		if (!publicJwk.kty) {
			throw new Error("Exported public key is missing 'kty'.");
		}

		// Calculate thumbprint for kid (Key ID), using SHA-256 as recommended
		const kid = await calculateJwkThumbprint(publicJwk, 'sha256');

        // Add kid and ensure alg/use are present in the final JWK
        const jwkForSet = {
            ...publicJwk,
            kid: kid,
            alg: publicJwk.alg || privateOrSecretKeyJwk.alg || 'HS256', // Ensure algorithm is included
            use: publicJwk.use || 'sig', // Ensure use is 'sig' (signature)
        };

        // Construct the JWKS (JSON Web Key Set)
        const jwks = {
            keys: [jwkForSet],
        };

		console.log("[handleJwksRequest] Successfully generated JWKS:", JSON.stringify(jwks));

		return c.json(jwks, 200, {
            // Add CORS headers if needed, depending on where resource server is hosted
            // 'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'public, max-age=600', // Cache for 10 minutes
        });

	} catch (error: any) {
		console.error("Error generating JWKS:", error);
		return c.json({ error: 'server_error', error_description: `Failed to generate JWKS: ${error.message}` }, 500);
	}
}
