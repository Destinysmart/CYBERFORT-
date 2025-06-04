const express = require('express');
const router = express.Router();
const axios = require('axios');

// URL Checker endpoint
router.post('/check-url', async (req, res) => {
  try {
    const { url } = req.body;
    console.log('Received URL check request for:', url);

    if (!url) {
      console.log('URL is missing in request');
      return res.status(400).json({ message: "URL is required" });
    }

    // Basic URL validation
    if (!url.match(/^(http|https):\/\/[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/.*)?$/)) {
      console.log('Invalid URL format:', url);
      return res.status(400).json({ message: "Invalid URL format" });
    }

    // Get API key from environment variable
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      console.error("VirusTotal API key not configured");
      return res.status(500).json({ message: "API configuration error" });
    }

    try {
      console.log('Submitting URL to VirusTotal:', url);
      // First, submit the URL for analysis
      const scanResponse = await axios.post(
        'https://www.virustotal.com/api/v3/urls',
        new URLSearchParams({ url }),
        {
          headers: {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'x-apikey': apiKey
          }
        }
      );

      // Extract the analysis ID from the response
      const analysisId = scanResponse.data.data.id;
      console.log('Got analysis ID:', analysisId);

      // Get the analysis report
      console.log('Fetching analysis report...');
      const reportResponse = await axios.get(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: {
            'accept': 'application/json',
            'x-apikey': apiKey
          }
        }
      );

      // Process the report results
      const report = reportResponse.data.data.attributes;
      const stats = report.stats;
      console.log('Analysis stats:', stats);

      // Determine if URL is safe based on malicious verdicts
      const isSafe = stats.malicious === 0 && stats.suspicious === 0;
      const result = isSafe 
        ? "No threats detected" 
        : `Detected as malicious by ${stats.malicious} and suspicious by ${stats.suspicious} security vendors`;

      console.log('URL check result:', { isSafe, result });

      return res.status(200).json({
        url,
        isSafe,
        result,
        stats: {
          total: stats.total,
          malicious: stats.malicious,
          suspicious: stats.suspicious,
          undetected: stats.undetected
        }
      });

    } catch (error) {
      console.error("VirusTotal API error:", error.response?.data || error.message);
      return res.status(500).json({ 
        message: "Error checking URL",
        details: error.response?.data?.error?.message || error.message
      });
    }
  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ 
      message: "Internal server error",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router; 