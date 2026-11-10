import { createApp } from './app.js';

const port = Number(process.env.PORT ?? 3000);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer from 1 to 65535.');
}

const server = createApp();
server.on('error', (error: NodeJS.ErrnoException) => {
  console.error(error.code === 'EADDRINUSE'
    ? `Port ${port} is already in use. Set PORT to use another port.`
    : 'Could not start the server.');
  process.exitCode = 1;
});
server.listen(port, '127.0.0.1', () => {
  console.log(`JWT Workbench is running at http://localhost:${port}`);
});
