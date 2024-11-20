import { type BinaryLike } from "node:crypto";

export interface CsrfOptions {
	secret: string;
}

export interface CsrfKeeper {
	create(randomValue: string, payload: BinaryLike): string;
	verify(token: string, payload: BinaryLike): boolean;
	randomToken(): string;
}
