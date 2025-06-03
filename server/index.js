const express = require('express');
const cors = require('cors');
const path = require('path');
const urlCheckerRouter = require('./routes/url-checker');

const app = express();

// Middleware
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? 'https://cyberfort-palq.onrender.com'  // Your frontend URL
    : 'http://localhost:5173',  // Vite's default dev server port
  credentials: true
}));
app.use(express.json());

// API Routes
app.use('/api', urlCheckerRouter);

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/dist')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/dist/index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 