const { spawn } = require('child_process');
const path = require('path');

// Start the server
const server = spawn('node', ['server/index.js'], {
  stdio: 'inherit',
  shell: true
});

// Start the client
const client = spawn('npm', ['run', 'dev'], {
  stdio: 'inherit',
  shell: true
});

// Handle process termination
process.on('SIGINT', () => {
  server.kill();
  client.kill();
  process.exit();
}); 