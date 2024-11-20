import { describe, expect, it, vi } from "vitest";
import { createCsrfKeeper } from "./csrf.js";
import crypto from "node:crypto";

describe("Signed Double-Submit Cookie", () => {
	const csrf = createCsrfKeeper({
		secret: crypto.randomUUID(),
	});

	it("should generate a random token", () => {
		const randomValue = csrf.randomToken();
		expect(randomValue).toHaveLength(64);
		expect(randomValue).toMatch(/^[0-9a-f]+$/);
	});

	it("should generate a csrf token with payload", () => {
		const sessionId = crypto.randomUUID();
		const randomValue = csrf.randomToken();
		const csrfToken = csrf.create(randomValue, sessionId);

		const [_, randomValueFromCsrf] = csrfToken.split(".");

		expect(randomValue).to.eq(randomValueFromCsrf);
	});

	it("should verify a csrf token", () => {
		const sessionId = crypto.randomUUID();
		const randomValue = csrf.randomToken();
		const csrfToken = csrf.create(randomValue, sessionId);

		expect(csrf.verify(csrfToken, sessionId)).to.eq(true);
	});
});
