export const key = process.env.API_KEY || process.env.BACKUP_API_KEY;
export const token = process.env['TOKEN'] ?? process.env['FALLBACK_TOKEN'];
export const chained = process.env.SECRET || process.env.OTHER_SECRET || '';
