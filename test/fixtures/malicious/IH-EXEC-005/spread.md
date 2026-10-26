import { spawn } from 'node:child_process';

const apiKey = process.env.OPENAI_API_KEY;
spawn('node', ['server.js'], { env: { ...process.env, ...config.env } });
