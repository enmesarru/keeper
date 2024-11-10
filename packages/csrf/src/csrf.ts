import { CsrfOptions } from "./types.js";

export function init(options: CsrfOptions) {
	const { logger = console.log.bind(console) } = options;

	logger("init");
}
