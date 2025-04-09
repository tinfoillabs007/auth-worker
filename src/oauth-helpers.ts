/**
 * @description
 * Helper functions for OAuth 2.1 operations within the Authentication Server Worker.
 * Includes utilities for random string generation, HTML escaping, and managing
 * temporary state storage in KV during the authorization flow.
 *
 * @dependencies
 * - @cloudflare/workers-types: Provides KVNamespace type.
 * - ./env: Provides the Env interface definition.
 * - @cloudflare/workers-oauth-provider: Provides AuthRequest type.
 *
 * @notes
 * - KV storage functions use a specific prefix (`oauth_session:`) for organization.
 * - TTL (Time To Live) is crucial for temporary state to prevent orphaned data.
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import type { Env } from './env'; // Assuming Env is defined in env.ts
import type { AuthRequest } from '@cloudflare/workers-oauth-provider'; // For TemporaryOAuthState

// --- Interfaces ---

/**
 * Extends the base AuthRequest with status and user ID information needed
 * during the multi-stage authorization flow handled by auth-handler.ts.
 */
export interface TemporaryOAuthState extends AuthRequest {
	status: 'pending_hanko_auth' | 'pending_consent';
	hankoUserId?: string; // Added after successful Hanko authentication
}

// --- Utility Functions ---

/**
 * Escapes special HTML characters in a string to prevent XSS.
 * @param unsafe The potentially unsafe string.
 * @returns The escaped string, or an empty string if input is null/undefined.
 */
export const escapeHtml = (unsafe: string | undefined | null): string => {
	if (!unsafe) return '';
	return unsafe
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;');
};

/**
 * Generates a cryptographically strong random string of a specified length.
 * Used for creating secure session IDs or state parameters.
 * @param length The desired length of the random string.
 * @returns A random string containing URL-safe characters (A-Z, a-z, 0-9, -, _).
 */
export function generateRandomString(length: number): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	// Convert bytes to a URL-safe base64-like string
	let result = '';
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
	for (let i = 0; i < array.length; i++) {
		const index = (array[i] as number) % chars.length;
		result += chars[index] as string;
	}
	return result;
}

// --- KV Storage Helpers for Temporary Auth State ---

const OAUTH_SESSION_KV_PREFIX = 'oauth_session:';

/**
 * Stores temporary OAuth state data in KV with a specific TTL.
 * @param env Worker environment containing OAUTH_KV binding.
 * @param sessionId The unique identifier for this authorization attempt.
 * @param data The TemporaryOAuthState object to store.
 * @param ttlSeconds Time To Live for the stored data in seconds.
 * @throws Error if OAUTH_KV is not available or if storing fails.
 */
export async function storeTemporaryOAuthState(env: Env, sessionId: string, data: TemporaryOAuthState, ttlSeconds: number): Promise<void> {
	if (!env.OAUTH_KV) {
		console.error('OAUTH_KV namespace is not available in env.');
		throw new Error('Storage configuration error (OAUTH_KV missing).');
	}
	const key = `${OAUTH_SESSION_KV_PREFIX}${sessionId}`;
	try {
		console.log(`Storing temporary OAuth state for session ${sessionId} with TTL ${ttlSeconds}s. Key: ${key}`);
		await env.OAUTH_KV.put(key, JSON.stringify(data), { expirationTtl: ttlSeconds });
		console.log(`Successfully stored state for session: ${sessionId}`);
	} catch (error: any) {
		console.error(`Failed to store temporary state in KV for key ${key}:`, error);
		throw new Error(`KV storage failed: ${error.message}`);
	}
}

/**
 * Retrieves temporary OAuth state data from KV.
 * @param env Worker environment containing OAUTH_KV binding.
 * @param sessionId The unique identifier for the authorization attempt.
 * @returns The stored TemporaryOAuthState object, or null if not found or expired.
 * @throws Error if OAUTH_KV is not available.
 */
export async function getTemporaryOAuthState(env: Env, sessionId: string): Promise<TemporaryOAuthState | null> {
	if (!env.OAUTH_KV) {
		console.error('OAUTH_KV namespace is not available in env.');
		throw new Error('Storage configuration error (OAUTH_KV missing).');
	}
	const key = `${OAUTH_SESSION_KV_PREFIX}${sessionId}`;
	try {
		console.log(`Retrieving temporary OAuth state for session ${sessionId}. Key: ${key}`);
		const data = await env.OAUTH_KV.get<TemporaryOAuthState>(key, { type: 'json' });
		if (data) {
			console.log(`Found state for session: ${sessionId}`);
		} else {
			console.log(`No state found for session: ${sessionId}`);
		}
		return data;
	} catch (error: any) {
		// KV get errors (like parse errors) might throw
		console.error(`Failed to retrieve or parse temporary state from KV for key ${key}:`, error);
		// Depending on policy, might return null or re-throw
		return null;
	}
}

/**
 * Deletes temporary OAuth state data from KV.
 * @param env Worker environment containing OAUTH_KV binding.
 * @param sessionId The unique identifier for the authorization attempt.
 * @throws Error if OAUTH_KV is not available or if deletion fails.
 */
export async function deleteTemporaryOAuthState(env: Env, sessionId: string): Promise<void> {
	if (!env.OAUTH_KV) {
		console.error('OAUTH_KV namespace is not available in env.');
		throw new Error('Storage configuration error (OAUTH_KV missing).');
	}
	const key = `${OAUTH_SESSION_KV_PREFIX}${sessionId}`;
	try {
		console.log(`Deleting temporary OAuth state for session ${sessionId}. Key: ${key}`);
		await env.OAUTH_KV.delete(key);
		console.log(`Successfully deleted state for session: ${sessionId}`);
	} catch (error: any) {
		console.error(`Failed to delete temporary state in KV for key ${key}:`, error);
		throw new Error(`KV deletion failed: ${error.message}`);
	}
}
