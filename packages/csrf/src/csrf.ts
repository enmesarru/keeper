import crypto from "node:crypto";
import { CsrfKeeper, CsrfOptions } from "./types.js";

/**
 * Create keeper instance for csrf primitives
 * It follows the signed double-submit cookie technique
 * @param {Object} options - Configuration options for CSRF protection
 * @param {string} options.secret - Secret key used for signing cookies and tokens
 * @returns {CsrfKeeper} Instance of CSRF protection mechanism
 * @throws {Error} Throws an error if secret is not provided or invalid
 */
function createCsrfKeeper(options: CsrfOptions): CsrfKeeper {
	const { secret } = options;

	if (!options.secret) {
		throw new Error("Secret key is required.");
	}

	function randomToken(): string {
		return crypto.randomBytes(32).toString("hex");
	}

	/**
	 * Create a csrf token
	 * @param {string} randomValue Random value for encryption
	 * @param {string} payload  A session-dependent value
	 * @returns {string}
	 */
	function create(randomValue: string, payload: crypto.BinaryLike): string {
		const message = `${payload}!${randomValue}`;
		const encryptedMessage = crypto
			.createHmac("sha256", secret)
			.update(message)
			.digest("hex");

		return `${encryptedMessage}.${randomValue}`;
	}

	/**
	 * Verify the csrf token
	 * @param {string} token CSRF token
	 * @param {string} payload A session-dependent value
	 * @returns {boolean}
	 */
	function verify(token: string, payload: crypto.BinaryLike): boolean {
		const [encryptedMessage, randomValue] = token.split(".");
		const message = `${payload}!${randomValue}`;

		const encrypted = crypto
			.createHmac("sha256", secret)
			.update(message)
			.digest("hex");

		return encrypted === encryptedMessage;
	}

	return {
		create,
		verify,
		randomToken,
	};
}

export { createCsrfKeeper };
