/**
 * @description
 * Cloudflare Worker entry point for the dedicated Authentication Server.
 * Uses Hono and integrates with @cloudflare/workers-oauth-provider.
 * Exports the provider's fetch method to handle OAuth routing.
 *
 * Responsibilities:
 * - Handle OAuth 2.1 authorization requests (/authorize) via defaultHandler.
 * - Handle token requests (/token) - Handled internally by OAuthProvider.
 * - Provide JWKS endpoint (/.well-known/jwks.json) - Now handled explicitly by defaultHandler.
 * - Potentially other auth-related utility endpoints via defaultHandler.
 *
 * @dependencies
 * - hono: Web framework for Cloudflare Workers.
 * - ./env: Type definition for environment bindings.
 * - ./oauth-config: Client registration and OAuth settings.
 * - ./oauth-helpers: Utility functions for state management.
 * - ./auth-handler: Implementation logic for /authorize and /jwks.json endpoints.
 * - @cloudflare/workers-oauth-provider: Core OAuth library.
 *
 * @notes
 * - Exports `provider.fetch` as the default handler.
 * - Requires wrangler.toml to provide OAUTH_KV binding and OAUTH_SIGNING_KEY secret.
 * - The defaultHandler (Hono app) will receive OAuthHelpers via c.env.OAUTH_PROVIDER.
 * - Assumes the library implicitly uses the OAUTH_KV binding for storage.
 * - Provider is instantiated per-request inside the fetch handler.
 */

import { Hono } from 'hono';
import type { Env } from './env';
import { REGISTERED_CLIENTS, ACCESS_TOKEN_LIFETIME_SECONDS, REFRESH_TOKEN_LIFETIME_SECONDS, AUTH_CODE_LIFETIME_SECONDS } from './oauth-config';
import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import type { OAuthHelpers, ClientInfo } from '@cloudflare/workers-oauth-provider'; // Import ClientInfo
import type { Context as HonoContext } from 'hono';
import type { ExecutionContext } from '@cloudflare/workers-types';
import { escapeHtml } from './oauth-helpers'; // Import escapeHtml
import {
	handleAuthorizeGetRequest,
	handleAuthorizePostHankoSuccess,
	handleAuthorizePostConsent,
	handleJwksRequest // Import the JWKS handler
} from './auth-handler';
// Import the new helper functions and types
import {
    generateTokenId,
    unwrapKeyWithToken,
    decryptProps,
    type Token as IntrospectionToken
} from './introspection-helpers';

// Define context type for handlers receiving OAuthHelpers via env
type HandlerContext = HonoContext<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>;

// --- Hono App for Default Routes (e.g., /, /authorize, /jwks.json, /introspect) ---
const defaultApp = new Hono<{ Bindings: Env }>();

// Basic root route
defaultApp.get('/', (c) => {
	console.log('Auth Server: Default handler processing root path.');
	return c.html('<h1>Authentication Server Worker</h1><p>Ready to handle OAuth requests.</p>');
});

// --- JWKS Endpoint Route ---
defaultApp.get('/.well-known/jwks.json', handleJwksRequest);

// --- Authorization Endpoint Routes ---
// Cast through 'unknown' first to satisfy TypeScript when adding OAUTH_PROVIDER
defaultApp.get('/authorize', (c) => handleAuthorizeGetRequest(c as unknown as HandlerContext));

defaultApp.post('/authorize', async (c) => {
    // Cast through 'unknown' first
	const handlerContext = c as unknown as HandlerContext;
	try {
        const formData = await c.req.formData();
		const flowStep = formData.get('flow_step') as string | null;
		console.log(`Handling POST /authorize request with flow_step: ${flowStep}`);

		if (flowStep === 'hanko_success') {
			return await handleAuthorizePostHankoSuccess(handlerContext);
		} else if (flowStep === 'consent_submit') {
			return await handleAuthorizePostConsent(handlerContext);
		} else {
			console.error(`Invalid or missing flow_step in POST /authorize: ${flowStep}`);
			return c.text('Invalid request flow.', 400);
		}
	} catch (error: any) {
		console.error("Error processing POST /authorize:", error);
        throw error; // Re-throw for the main onError handler
	}
});

// --- Introspection Endpoint Route (RFC 7662) ---
defaultApp.post('/introspect', async (c) => {
    try {
        const formData = await c.req.formData();
        const token = formData.get('token') as string | null;
        const tokenTypeHint = formData.get('token_type_hint') as string | null; // Optional hint

        if (!token) {
            return c.json({ error: 'invalid_request', error_description: 'Token is required.' }, 400);
        }

        // We only support access tokens for introspection here
        if (tokenTypeHint && tokenTypeHint !== 'access_token') {
             console.log(`[Introspect] Unsupported token_type_hint: ${tokenTypeHint}`);
             return c.json({ active: false, reason: 'Unsupported token type hint' });
        }

        // Parse token structure: {userId}:{grantId}:{secret}
        const tokenParts = token.split(':');
        if (tokenParts.length !== 3) {
            console.log('[Introspect] Invalid token format received.');
            return c.json({ active: false, reason: 'Invalid token format' });
        }
        const [userId, grantId, _] = tokenParts;

        // Generate the token ID hash (same logic as the provider library)
        const tokenId = await generateTokenId(token);
        const tokenKey = `token:${userId}:${grantId}:${tokenId}`;
        console.log(`[Introspect] Looking up token key: ${tokenKey}`);

        // Fetch token data from KV
        const tokenData: IntrospectionToken | null = await c.env.OAUTH_KV.get(tokenKey, { type: 'json' });

        if (!tokenData) {
            console.log('[Introspect] Token not found in KV.');
            return c.json({ active: false, reason: 'Token not found' });
        }

        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (tokenData.expiresAt < now) {
            console.log('[Introspect] Token expired.');
            return c.json({ active: false, reason: 'Token expired' });
        }

        // Token is active and valid, try to decrypt props
        let decryptedProps: any = {};
        try {
            const encryptionKey = await unwrapKeyWithToken(token, tokenData.wrappedEncryptionKey);
            decryptedProps = await decryptProps(encryptionKey, tokenData.grant.encryptedProps);
            console.log('[Introspect] Props decrypted successfully.');
        } catch (decryptError: any) {
            console.error('[Introspect] Failed to decrypt props:', decryptError);
            // Proceed without props, but log the error
        }

        // Construct RFC 7662 compliant response
        const introspectionResponse = {
            active: true,
            scope: tokenData.grant.scope.join(' '),
            client_id: tokenData.grant.clientId,
            sub: tokenData.userId, // Subject (user identifier)
            exp: tokenData.expiresAt, // Expiration time
            iat: tokenData.createdAt, // Issued at time
            token_type: 'bearer',
            // Include decrypted props directly in the response
            ...decryptedProps
        };

        console.log('[Introspect] Token validated successfully.');
        return c.json(introspectionResponse);

    } catch (error: any) {
        console.error('Error during token introspection:', error);
        // Return inactive on any internal error
        return c.json({ active: false, reason: 'Internal server error during introspection' }, 500);
    }
});


// Default 404 for routes not handled by defaultApp
defaultApp.notFound((c) => {
  console.log(`Default handler (defaultApp) Not Found: ${c.req.path}`);
  return c.text('Not Found via Default Handler', 404);
});

// Error handler for defaultApp - Catches errors from route handlers
defaultApp.onError(async (err, c) => {
  console.error(`Default Handler (authApp) Caught Error: ${err.message}`, err.stack);

  // Attempt OAuth-style error redirect if possible (only makes sense for /authorize flow errors)
  if (c.req.path.startsWith('/authorize')) {
      const redirectUri = (err as any)?.redirect_uri;
      const state = (err as any)?.state;
      const oauthError = (err as any)?.error || 'server_error';
      const errorDescription = (err as any)?.error_description || err.message || 'An internal error occurred.';

      if (redirectUri) {
        try {
          const errorRedirectUrl = new URL(redirectUri);
          errorRedirectUrl.searchParams.set('error', oauthError);
          errorRedirectUrl.searchParams.set('error_description', errorDescription);
          if (state !== undefined) {
              errorRedirectUrl.searchParams.set('state', state);
          }
          console.log(`onError: Redirecting with error to: ${errorRedirectUrl.toString()}`);
          return c.redirect(errorRedirectUrl.toString());
        } catch (e) {
          console.error("Error constructing/parsing error redirect URL in onError:", e);
        }
      }
  }

  // Fallback generic error (especially for /introspect or other non-authorize routes)
   return c.json({ error: 'server_error', error_description: err.message || 'An internal server error occurred.' }, 500);
});


// --- Function to get OAuthProvider Options ---
function getProviderOptions(request: Request, env: Env) {
    const issuer = env.OAUTH_ISSUER_URL || new URL(request.url).origin;
    console.log(`[getProviderOptions] Using issuer: ${issuer}`);
    console.log(`[getProviderOptions] Using static clients array:`, JSON.stringify(REGISTERED_CLIENTS));

    // Prepare options for the OAuthProvider library
    // Note: The /introspect endpoint is handled by our defaultApp, not the library itself
    const providerOptions = {
        clients: REGISTERED_CLIENTS,
        issuer: issuer,
        signingKey: env.OAUTH_SIGNING_KEY, // Still needed for JWKS signing if used elsewhere
        authCodeLifetime: AUTH_CODE_LIFETIME_SECONDS,
        accessTokenLifetime: ACCESS_TOKEN_LIFETIME_SECONDS, // Used by library for token record TTL
        refreshTokenLifetime: REFRESH_TOKEN_LIFETIME_SECONDS,
        authorizeEndpoint: '/authorize',
        tokenEndpoint: '/token', // Handled by library
        jwksEndpoint: '/.well-known/jwks.json', // Handled by defaultApp
        clientRegistrationEndpoint: '/register',
        // apiRoute and apiHandler are handled by library if requests match
        apiRoute: '/api/', // Define the base path for API routes handled by this handler
        apiHandler: { 
            // This handler receives requests ONLY if they have a valid access token matching /api/
            async fetch(
                request: Request,
                env: Env & { OAUTH_PROVIDER: OAuthHelpers }, // Env might include helpers here too
                ctx: ExecutionContext & { props?: Record<string, any> } // Context includes props!
            ): Promise<Response> {
                 const url = new URL(request.url);
                 console.log(`[apiHandler] Received request for ${url.pathname}`);
                 
                 // ---> Implement /api/me endpoint <-----
                 if (url.pathname === '/api/me') {
                     const userProps = ctx.props; // Get props associated with the access token
                     console.log("[api/me] User props from token:", userProps);

                     // Return only what's available in props
                     const userInfo = {
                         hankoUserId: userProps?.hankoUserId || null // Use optional chaining
                         // Remove email/name as they are no longer passed in props
                         // email: userProps?.email,
                         // name: userProps?.name || null,
                     };
                     console.log("[api/me] Returning user info:", userInfo);
                     return new Response(JSON.stringify(userInfo), { status: 200, headers: { 'Content-Type': 'application/json' } });
                 }
                 // ---> End /api/me endpoint <-----
                 
                 // Default 404 for other /api/ routes not handled
                 console.log(`[apiHandler] Path ${url.pathname} not found.`);
                 return new Response(JSON.stringify({
                    error: 'not_found',
                    message: `API endpoint ${url.pathname} not found.`
                 }), {
                    status: 404,
                    headers: { 'Content-Type': 'application/json' }
                 });
            }
        },
        // Pass our Hono app (which now includes /introspect) as the defaultHandler
        defaultHandler: {
            async fetch(request: Request, handlerEnv: any, ctx: ExecutionContext): Promise<Response> {
                console.log(`Auth Server: defaultHandler fetch wrapper invoked (URL: ${request.url}), delegating to defaultApp.fetch`);
                return defaultApp.fetch(request, handlerEnv as Env, ctx);
            }
        },
        // Assuming tokenExchangeCallback is not needed for now
        // tokenExchangeCallback: async (options) => { /* ... */ }
    };
    // Remove properties the library might not expect or handle gracefully now
    // delete providerOptions.jwksEndpoint; // Handled by defaultApp
    // delete providerOptions.authorizeEndpoint; // Handled by defaultApp? No, library uses for metadata.

    return providerOptions;
}

// --- Export Fetch Handler ---
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		try {
            // --- Runtime Checks for Critical Env Vars ---
			if (!env.OAUTH_SIGNING_KEY) {
				console.error("CRITICAL: OAUTH_SIGNING_KEY secret is not set in the environment!");
				return new Response("Internal Server Error: Auth provider configuration missing (Signing Key).", { status: 500 });
			}
			if (!env.OAUTH_KV) {
				console.error("CRITICAL: OAUTH_KV binding is not set in the environment!");
				return new Response("Internal Server Error: Auth provider storage configuration missing (KV Binding).", { status: 500 });
			}
             if (!env.OAUTH_ISSUER_URL) {
				console.warn("WARNING: OAUTH_ISSUER_URL is not set. Defaulting to worker origin. Ensure this is correct for production.");
			}


            // --- Instantiate Provider Per-Request ---
            const options = getProviderOptions(request, env);
            console.log("[fetch] Instantiating OAuthProvider with option keys:", Object.keys(options));

            // Ensure OAUTH_PROVIDER helpers are available for the Hono app via env
            // The library *should* add this, but let's be safe if defaultHandler is called directly somehow
            if (!env.OAUTH_PROVIDER) {
                 // @ts-ignore - Library creates internal impl, we can't directly instantiate OAuthHelpersImpl
                 // This part is tricky - the library's internal helpers might be needed by handlers.
                 // Relying on the library to correctly populate env.OAUTH_PROVIDER when calling defaultHandler.
                 console.warn("[fetch] env.OAUTH_PROVIDER not yet set before provider instantiation.");
            }

            // @ts-ignore - Suppress potential type mismatch issues if library types are problematic
            const provider = new OAuthProvider(options);
            console.log("[fetch] OAuthProvider instantiated. Calling provider.fetch...");

            // The provider will route requests based on its config.
            // Our defaultApp (via options.defaultHandler) handles /, /authorize, /jwks.json, /introspect
            // The library handles /token internally.
            // The library might handle /api/ based on apiRoute/apiHandler config.
            return await provider.fetch(request, env, ctx);

		} catch (error: any) {
			console.error("Failed to initialize or run OAuthProvider:", error);
			// Ensure a Response object is returned
			return new Response(`Internal Server Error: ${escapeHtml(error.message)}`, { status: 500 });
		}
	},
};
