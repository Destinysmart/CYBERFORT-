const express = require('express');
const router = express.Router();
const axios = require('axios');

const VIRUSTOTAL_API_KEY = "fa445174a59c7519b96f92c1a1897ff5eb0d0a3051c0130ea7a039e63da29966";

router.post('/check-url', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ message: "URL is required" });
    }

    // First, submit the URL for analysis
    const scanResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }),
      {
        headers: {
          'accept': 'application/json',
          'content-type': 'application/x-www-form-urlencoded',
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );

    // Extract the analysis ID from the response
    const analysisId = scanResponse.data.data.id;

    // Get the analysis report
    const reportResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'accept': 'application/json',
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );

    // Process the report results
    const report = reportResponse.data.data.attributes;
    const stats = report.stats;

    // Calculate risk score based on VirusTotal stats
    let riskScore = 0;
    let issues = [];

    // Add points based on malicious and suspicious verdicts
    if (stats.malicious > 0) {
      riskScore += (stats.malicious / stats.total) * 100;
      issues.push(`${stats.malicious} security vendors flagged this as malicious`);
    }
    if (stats.suspicious > 0) {
      riskScore += (stats.suspicious / stats.total) * 50;
      issues.push(`${stats.suspicious} security vendors flagged this as suspicious`);
    }

    // Check SSL/TLS
    let sslIssues = [];
    if (report.ssl_info) {
      if (!report.ssl_info.is_valid) {
        sslIssues.push("Invalid SSL certificate");
      }
      if (report.ssl_info.is_expired) {
        sslIssues.push("SSL certificate is expired");
      }
      if (report.ssl_info.is_self_signed) {
        sslIssues.push("SSL certificate is self-signed");
      }
    }

    // Determine if safe
    const isSafe = riskScore < 50;

    // Format response
    return res.json({
      url,
      isSafe,
      result: issues.length > 0 ? issues.join(", ") : "No threats detected",
      sslIssues: sslIssues.length > 0 ? sslIssues : undefined,
      hasSslIssues: sslIssues.length > 0,
      riskScore: Math.min(riskScore, 100),
      stats: {
        total: stats.total,
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        undetected: stats.undetected
      }
    });

  } catch (error) {
    console.error('URL check error:', error);
    
    if (error.response?.status === 401) {
      return res.status(500).json({ message: "Invalid VirusTotal API key" });
    } else if (error.response?.status === 429) {
      return res.status(429).json({ message: "Rate limit exceeded. Please try again in a few minutes." });
    } else {
      return res.status(500).json({ message: "Error checking URL" });
    }
  }
});

module.exports = router; 