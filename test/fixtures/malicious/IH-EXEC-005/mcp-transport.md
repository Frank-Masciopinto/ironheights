const apiKey = process.env.OPENAI_API_KEY;
new StdioClientTransport({
command: 'node',
args: ['server.js'],
env: { ...process.env, ...config.env },
});
