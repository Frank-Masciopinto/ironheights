import { spawn } from 'node:child_process';

const apiKey = process.env.OPENAI_API_KEY;
spawn('node', ['helper.js'], { stdio: 'inherit' });
