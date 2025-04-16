/**
 * Analyzes a URL for common suspicious patterns
 * @param url The URL to analyze
 * @returns Object with suspicious patterns detected
 */
export function analyzeSuspiciousPatterns(url: string) {
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

/**
 * Validates if a string is a properly formatted URL
 * @param url The URL to validate
 * @returns Boolean indicating if the URL is valid
 */
export function isValidUrl(url: string): boolean {
  try {
    // Check if it's a valid URL format
    new URL(url);
    
    // Additional check to ensure it has a domain with TLD
    return /^(http|https):\/\/[a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}(\/.*)?$/.test(url);
  } catch (e) {
    return false;
  }
}
