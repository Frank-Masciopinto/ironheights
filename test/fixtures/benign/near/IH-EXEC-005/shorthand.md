const PATH = process.env.PATH ?? '';
const HOME = process.env.HOME ?? '';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY ?? '';
spawn('tool', { env: { PATH, HOME, OPENAI_API_KEY } });
