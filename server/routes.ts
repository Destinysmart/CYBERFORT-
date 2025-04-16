import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import express from "express";
import axios from "axios";
import { z } from "zod";
import { insertUrlCheckSchema, insertPhoneCheckSchema } from "@shared/schema";

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
      
      // Check for common suspicious patterns
      const suspicious = checkSuspiciousPatterns(url);
      
      // For a production app, we would integrate with VirusTotal API here
      // This is a simplified version that checks basic heuristics
      const isSafe = !suspicious.hasSuspiciousPatterns;
      const result = isSafe ? "No threats detected" : suspicious.reasons.join(", ");
      
      // Save the check result to storage
      const urlCheckData = {
        url,
        isSafe,
        result
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
        history
      });
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
      const cleaned = phoneNumber.replace(/\D/g, '');
      if (cleaned.length < 10) {
        return res.status(400).json({ message: "Invalid phone number format" });
      }
      
      try {
        // Use numverify API or similar (we'll use a fallback method here)
        const phoneData = await checkPhoneNumber(phoneNumber);
        
        // Determine if the number is safe (low risk score)
        const isSafe = phoneData.riskScore < 50;
        
        // Save the check result to storage
        const phoneCheckData = {
          phoneNumber,
          isSafe,
          country: phoneData.country,
          carrier: phoneData.carrier,
          lineType: phoneData.lineType,
          riskScore: phoneData.riskScore,
          details: phoneData.details
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
      } catch (error) {
        console.error("Error checking phone number:", error);
        return res.status(500).json({ message: "Failed to check phone number" });
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

// Helper functions
function checkSuspiciousPatterns(url: string) {
  const suspiciousPatterns = [
    { pattern: /\.(xyz|tk|ml|ga|cf|gq|pw)\//, reason: "Suspicious TLD" },
    { pattern: /(login|signin|account|secure|security|verify|verification)/, reason: "Potential phishing keywords" },
    { pattern: /[0-9a-f]{32}/, reason: "Suspicious random string" },
    { pattern: /\.(exe|bin|dll|scr|bat|cmd|msi)$/, reason: "Suspicious file extension" },
    { pattern: /^(http:\/\/)/, reason: "Insecure protocol (HTTP)" },
    { pattern: /^https?:\/\/\d+\.\d+\.\d+\.\d+/, reason: "IP address in URL" },
    { pattern: /@/, reason: "URL contains @ symbol" },
    { pattern: /bitly|tinyurl|goo\.gl|t\.co|bit\.ly/, reason: "URL shortener" }
  ];
  
  const reasons: string[] = [];
  suspiciousPatterns.forEach(({ pattern, reason }) => {
    if (pattern.test(url)) {
      reasons.push(reason);
    }
  });
  
  return {
    hasSuspiciousPatterns: reasons.length > 0,
    reasons
  };
}

async function checkPhoneNumber(phoneNumber: string) {
  // For production, you would use a real API like numverify, phonevalidator, etc.
  // This is a fallback implementation
  
  const countryMap: Record<string, string> = {
    "1": "United States",
    "44": "United Kingdom",
    "61": "Australia",
    "33": "France",
    "49": "Germany",
    "81": "Japan",
    "86": "China",
    "91": "India"
  };
  
  const carrierMap: Record<string, string[]> = {
    "1": ["AT&T", "Verizon", "T-Mobile", "Sprint"],
    "44": ["Vodafone", "EE", "O2", "Three"],
    "61": ["Telstra", "Optus", "Vodafone"],
    "33": ["Orange", "SFR", "Free Mobile"],
    "49": ["T-Mobile", "Vodafone", "O2"],
    "81": ["NTT DoCoMo", "au", "SoftBank"],
    "86": ["China Mobile", "China Unicom", "China Telecom"],
    "91": ["Jio", "Airtel", "Vodafone Idea"]
  };
  
  // Remove non-digits
  const cleaned = phoneNumber.replace(/\D/g, '');
  
  // Extract country code based on first digits
  let countryCode = "1"; // Default to US
  if (cleaned.startsWith("1")) {
    countryCode = "1";
  } else if (cleaned.startsWith("44")) {
    countryCode = "44";
  } else if (cleaned.startsWith("61")) {
    countryCode = "61";
  } else if (cleaned.startsWith("33")) {
    countryCode = "33";
  } else if (cleaned.startsWith("49")) {
    countryCode = "49";
  } else if (cleaned.startsWith("81")) {
    countryCode = "81";
  } else if (cleaned.startsWith("86")) {
    countryCode = "86";
  } else if (cleaned.startsWith("91")) {
    countryCode = "91";
  }
  
  const country = countryMap[countryCode] || "Unknown";
  const carriers = carrierMap[countryCode] || ["Unknown"];
  const carrier = carriers[Math.floor(Math.random() * carriers.length)];
  
  // Generate a risk score (would be provided by real API)
  // For demo, generate a random score but weight certain patterns
  let riskScore = Math.floor(Math.random() * 100);
  
  // Increase risk for repeated digits
  const digitCounts: Record<string, number> = {};
  for (const digit of cleaned) {
    digitCounts[digit] = (digitCounts[digit] || 0) + 1;
  }
  
  const maxRepeats = Math.max(...Object.values(digitCounts));
  if (maxRepeats > 4) {
    riskScore += 20;
  }
  
  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);
  
  // Return phone data
  return {
    phoneNumber,
    country,
    carrier,
    lineType: "Mobile",
    riskScore,
    details: {
      valid: true,
      spamReports: riskScore > 50 ? Math.floor(Math.random() * 50) + 5 : 0,
      formatted: formatPhoneNumber(cleaned, countryCode)
    }
  };
}

function formatPhoneNumber(cleaned: string, countryCode: string) {
  // Simple formatter for demo purposes
  if (countryCode === "1") {
    // US format
    return `+1 (${cleaned.slice(1, 4)}) ${cleaned.slice(4, 7)}-${cleaned.slice(7, 11)}`;
  } else {
    // Generic international format
    return `+${countryCode} ${cleaned.slice(countryCode.length)}`;
  }
}
