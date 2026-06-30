export class ColorTerm {
    private static colors = {
        INFO: '\x1b[32m',    // Green
        ERROR: '\x1b[31m',   // Red
        WARN: '\x1b[33m',    // Yellow
        DEBUG: '\x1b[36m',  // Cyan
        TIMESTAMP: '\x1b[34m', // Blue
        RESET: '\x1b[0m'
    };

    static colorize(text: string): string {
        // Matches timestamps like 2024-06-10 12:34:56
        const timestampRegex = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/g;
        // Matches ISO 8601 timestamps like 2025-06-13T01:17:16.008Z
        const isoTimestampRegex = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z/g;
        const infoRegex = / INFO |"info"/g;
        const errorRegex = / ERROR |"error"/g;
        const warnRegex = / WARN |"warn"/g;
        return text
            .replace(isoTimestampRegex, match => `${this.colors.TIMESTAMP}${match}${this.colors.RESET}`)
            .replace(timestampRegex, match => `${this.colors.TIMESTAMP}${match}${this.colors.RESET}`)
            .replace(infoRegex, match => `${this.colors.INFO}${match}${this.colors.RESET}`)
            .replace(errorRegex, match => `${this.colors.ERROR}${match}${this.colors.RESET}`)
            .replace(warnRegex, match => `${this.colors.WARN}${match}${this.colors.RESET}`)
            .replace(/ DEBUG |"debug"/g, match => `${this.colors.DEBUG}${match}${this.colors.RESET}`);
    }
}