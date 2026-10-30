import { spawn } from 'node:child_process';

spawn('node', ['server.js'], {
env: {
PATH: process.env.PATH,
HOME: process.env.HOME,
OPENAI_API_KEY: process.env.OPENAI_API_KEY,
},
});
