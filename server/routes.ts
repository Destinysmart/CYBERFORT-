import type { Express, Request } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import express from "express";
import axios from "axios";
import { z } from "zod";
import { insertUrlCheckSchema, insertPhoneCheckSchema } from "@shared/schema";
import https from "https";
import { URL } from "url";

export async function registerRoutes(app: Express): Promise<Server> {
  const apiRouter = express.Router();

  // URL Checker endpoint
  apiRouter.post("/check-url", async (req, res) => {
    try {
      const { url } = req.body;

      if (!url) {
        return res.status(400).json({ message: "URL is required" });
      }

      // Basic URL validation
      if (!url.match(/^(http|https):\/\/[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/.*)?$/)) {
        return res.status(400).json({ message: "Invalid URL format" });
      }

      // Check URL using VirusTotal API
      if (!process.env.VIRUSTOTAL_API_KEY) {
        return res.status(500).json({ message: "VirusTotal API key not configured" });
      }

      try {
        // Using VirusTotal API v3
        // First, get a scan ID by submitting the URL
        const scanResponse = await axios.post(
          'https://www.virustotal.com/api/v3/urls', 
          new URLSearchParams({ url }),
          {
            headers: {
              'x-apikey': process.env.VIRUSTOTAL_API_KEY,
              'Content-Type': 'application/x-www-form-urlencoded'
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
              'x-apikey': process.env.VIRUSTOTAL_API_KEY
            }
          }
        );

        // Process the report results
        const report = reportResponse.data.data.attributes;
        const stats = report.stats;

        // Determine if URL is safe based on malicious verdicts from VirusTotal
        let isSafe = stats.malicious === 0 && stats.suspicious === 0;
        let result = isSafe 
          ? "No threats detected" 
          : `Detected as malicious by ${stats.malicious} and suspicious by ${stats.suspicious} security vendors`;

        // Check SSL certificate for HTTPS URLs
        let sslIssues: string[] = [];
        let hasSslIssues = false;

        try {
          // Only check SSL for HTTPS URLs
          if (url.startsWith('https://')) {
            const sslCheck = await checkSSLCertificate(url);
            if (!sslCheck.isValid) {
              hasSslIssues = true;
              sslIssues = sslCheck.issues;

              // If VirusTotal thinks it's safe but SSL has issues, modify the result
              if (isSafe) {
                result = `No malware detected, but SSL certificate has issues: ${sslIssues.join('; ')}`;
                // Do not mark as unsafe based only on SSL issues, but add a warning
              }
            }
          }
        } catch (sslError) {
          console.error("Error checking SSL certificate:", sslError);
        }

        // Save the check result to storage with SSL information
        const urlCheckData = {
          url,
          isSafe,
          result: hasSslIssues && isSafe 
            ? `No malware detected, but SSL certificate has issues`
            : result,
          checkedAt: new Date()
        };

        // Validate against schema
        const validatedData = insertUrlCheckSchema.parse(urlCheckData);
        const savedCheck = await storage.createUrlCheck(validatedData);

        // Get recent history
        const history = await storage.getRecentUrlChecks(10);

        return res.status(200).json({
          url,
          isSafe,
          result,
          sslIssues: sslIssues.length > 0 ? sslIssues : undefined,
          hasSslIssues,
          history
        });

      } catch (error: any) {
        console.error("Error calling VirusTotal API:", error?.message || 'Unknown error');

        // If API is rate limited or fails, fallback to a safe response
        return res.status(500).json({ 
          message: "Unable to check URL with VirusTotal. API error or rate limit exceeded." 
        });
      }
    } catch (error) {
      console.error("Error checking URL:", error);
      return res.status(500).json({ message: "Failed to check URL" });
    }
  });

  // Phone Checker endpoint
  apiRouter.post("/check-phone", async (req, res) => {
    try {
      const { phoneNumber } = req.body;

      if (!phoneNumber) {
        return res.status(400).json({ message: "Phone number is required" });
      }

      // Basic phone number validation
      let cleaned = phoneNumber.replace(/\D/g, '');
      if (cleaned.length < 10) {
        return res.status(400).json({ message: "Invalid phone number format" });
      }

      // Check if AbstractAPI key is available
      if (!process.env.ABSTRACTAPI_API_KEY) {
        return res.status(500).json({ message: "AbstractAPI API key not configured" });
      }

      try {
        // Format number for E.164 standard if needed
        let formattedNumber = phoneNumber;

        // If number doesn't start with +, try to determine country code
        if (!phoneNumber.startsWith('+')) {
          // Check common prefixes for Nigerian numbers
          if (cleaned.startsWith('0') && cleaned.length === 11) {
            // Nigerian number - convert to international format
            formattedNumber = `+234${cleaned.substring(1)}`;
          } else if (cleaned.length === 10 && !cleaned.startsWith('0')) {
            // Assume US/Canada for 10-digit numbers
            formattedNumber = `+1${cleaned}`;
          } else {
            // Generic international prefix
            formattedNumber = `+${cleaned}`;
          }
        }

        // Call AbstractAPI to validate the phone number
        const apiUrl = `https://phonevalidation.abstractapi.com/v1/?api_key=${process.env.ABSTRACTAPI_API_KEY}&phone=${encodeURIComponent(formattedNumber)}`;

        const apiResponse = await axios.get(apiUrl);
        const data = apiResponse.data;

        if (!data) {
          throw new Error("Invalid response from AbstractAPI");
        }

        // Calculate a risk score based on AbstractAPI data
        let riskScore = 0;

        // If number is invalid, high risk
        if (!data.valid) riskScore += 70;

        // If it's a VOIP number (could be spam)
        if (data.type === "voip") riskScore += 30;

        // Cap risk score at 100
        riskScore = Math.min(riskScore, 100);

        // Determine if the number is safe (low risk score)
        const isSafe = riskScore < 50;

        // Map API response to our format
        const phoneData = {
          phoneNumber: formattedNumber,
          country: data.country?.name || "Unknown",
          carrier: data.carrier || "Unknown",
          lineType: data.type || "Unknown",
          riskScore,
          details: {
            valid: data.valid,
            formatted: data.format?.international || formattedNumber,
            location: data.location || "",
            spamReports: 0 // AbstractAPI doesn't provide spam reports
          }
        };

        // Save the check result to storage
        const phoneCheckData = {
          phoneNumber: formattedNumber,
          isSafe,
          country: phoneData.country,
          carrier: phoneData.carrier,
          lineType: phoneData.lineType,
          riskScore: phoneData.riskScore,
          details: phoneData.details,
          checkedAt: new Date()
        };

        // Validate against schema
        const validatedData = insertPhoneCheckSchema.parse(phoneCheckData);
        const savedCheck = await storage.createPhoneCheck(validatedData);

        // Get recent history
        const history = await storage.getRecentPhoneChecks(10);

        return res.status(200).json({
          ...phoneData,
          isSafe,
          history
        });
      } catch (error: any) {
        console.error("Error checking phone number with AbstractAPI:", error?.message || 'Unknown error');
        return res.status(500).json({ 
          message: "Unable to check phone number with AbstractAPI. API error or rate limit exceeded." 
        });
      }
    } catch (error) {
      console.error("Error in phone check route:", error);
      return res.status(500).json({ message: "Failed to check phone number" });
    }
  });

  // Get URL check history
  apiRouter.get("/url-history", async (req, res) => {
    try {
      const history = await storage.getRecentUrlChecks(10);
      return res.status(200).json(history);
    } catch (error) {
      console.error("Error getting URL history:", error);
      return res.status(500).json({ message: "Failed to get URL history" });
    }
  });

  // Get phone check history
  apiRouter.get("/phone-history", async (req, res) => {
    try {
      const history = await storage.getRecentPhoneChecks(10);
      return res.status(200).json(history);
    } catch (error) {
      console.error("Error getting phone history:", error);
      return res.status(500).json({ message: "Failed to get phone history" });
    }
  });

  // Register the API router
  app.use("/api", apiRouter);

  const httpServer = createServer(app);
  return httpServer;
}

// Helper function to check SSL/TLS certificate validity
async function checkSSLCertificate(urlString: string): Promise<{ isValid: boolean; issues: string[] }> {
  return new Promise((resolve) => {
    try {
      const issues: string[] = [];
      const parsedUrl = new URL(urlString);

      // Only check HTTPS URLs
      if (parsedUrl.protocol !== 'https:') {
        issues.push('Not using HTTPS (secure connection)');
        return resolve({ isValid: false, issues });
      }

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || 443,
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'HEAD',
        timeout: 5000, // 5 second timeout
        rejectUnauthorized: false, // Don't reject invalid certs - we want to check them
      };

      const req = https.request(options, (res) => {
        // Get certificate information from TLS socket
        // @ts-ignore - getPeerCertificate exists on TLSSocket but type definitions may not include it
        const cert = res.socket?.getPeerCertificate ? res.socket.getPeerCertificate() : null;

        if (!cert || Object.keys(cert).length === 0) {
          issues.push('No SSL certificate found');
          return resolve({ isValid: false, issues });
        }

        // Check certificate expiration
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const now = new Date();

        if (now < validFrom || now > validTo) {
          issues.push(`Certificate expired or not yet valid (valid from ${validFrom.toLocaleDateString()} to ${validTo.toLocaleDateString()})`);
        }

        // Check domain/CN mismatch
        if (cert.subject) {
          const cn = cert.subject.CN;

          // Check common name directly
          if (cn && !matchesDomain(parsedUrl.hostname, cn)) {
            // Also check subject alternative names if available
            const altNames = cert.subjectaltname?.split(', ').map((name: string) => {
              return name.startsWith('DNS:') ? name.substring(4) : name;
            }) || [];

            let hasMatch = false;
            for (const altName of altNames) {
              if (matchesDomain(parsedUrl.hostname, altName)) {
                hasMatch = true;
                break;
              }
            }

            if (!hasMatch) {
              issues.push(`Certificate domain mismatch (cert: ${cn}, requested: ${parsedUrl.hostname})`);
            }
          }
        }

        // Check if there are any issues
        resolve({ isValid: issues.length === 0, issues });
      });

      req.on('error', (error) => {
        issues.push(`SSL connection error: ${error.message}`);
        resolve({ isValid: false, issues });
      });

      req.on('timeout', () => {
        req.destroy();
        issues.push('Connection timed out');
        resolve({ isValid: false, issues });
      });

      req.end();
    } catch (error: any) {
      resolve({ isValid: false, issues: [`Error checking SSL: ${error.message}`] });
    }
  });
}

// Helper function to check if domain matches certificate name (with wildcard support)
function matchesDomain(hostname: string, certName: string): boolean {
  // Convert to lowercase for comparison
  hostname = hostname.toLowerCase();
  certName = certName.toLowerCase();

  // Exact match
  if (hostname === certName) {
    return true;
  }

  // Check wildcard match
  if (certName.startsWith('*.')) {
    const certDomain = certName.substring(2);
    return hostname.endsWith(certDomain) && hostname.lastIndexOf('.') > 0;
  }

  return false;
}