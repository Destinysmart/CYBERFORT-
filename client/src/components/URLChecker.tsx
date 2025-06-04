import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import CollapsibleHistory from "./CollapsibleHistory";
import axios from "axios";
import { STORAGE_KEYS, getStoredHistory, addToHistory } from "@/lib/storage";

interface HistoryItem {
  id: number;
  title: string;
  subtitle: string;
  timestamp: string;
  status: "safe" | "unsafe";
}

interface UrlCheckResult {
  id: number;
  url: string;
  isSafe: boolean;
  result: string;
  checkedAt: string;
}

export default function URLChecker() {
  const [url, setUrl] = useState("");
  const [urlHistory, setUrlHistory] = useState<UrlCheckResult[]>([]);
  const [checkResult, setCheckResult] = useState<{
    isSafe: boolean;
    result: string;
    url: string;
    sslIssues?: string[];
    hasSslIssues?: boolean;
    stats: {
      total: number;
      malicious: number;
      suspicious: number;
      undetected: number;
    };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load history from localStorage on component mount
  useEffect(() => {
    const storedHistory = getStoredHistory<UrlCheckResult>(STORAGE_KEYS.URL_HISTORY);
    setUrlHistory(storedHistory);
  }, []);

  // URL check mutation
  const checkUrlMutation = useMutation({
    mutationFn: async (urlToCheck: string) => {
      // Preprocess and validate URL
      let processedUrl = urlToCheck.trim();
      
      // Add http:// if no protocol is specified
      if (!processedUrl.startsWith('http://') && !processedUrl.startsWith('https://')) {
        processedUrl = `http://${processedUrl}`;
      }

      // Basic URL validation
      try {
        new URL(processedUrl);
      } catch (e) {
        throw new Error("Invalid URL format. Please enter a valid URL.");
      }

      // Get API key from environment variable
      const apiKey = "fa445174a59c7519b96f92c1a1897ff5eb0d0a3051c0130ea7a039e63da29966";

      try {
        // First, submit the URL for analysis
        const scanResponse = await axios.post(
          'https://www.virustotal.com/api/v3/urls',
          new URLSearchParams({ url: processedUrl }),
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

        // Get the analysis report
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

        // Calculate risk score based on VirusTotal stats
        let riskScore = 0;
        let issues: string[] = [];

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
        let sslIssues: string[] = [];
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
        return {
          url: processedUrl,
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
        };
      } catch (error: any) {
        if (error.response?.status === 401) {
          throw new Error("Invalid VirusTotal API key. Please check your API key configuration.");
        } else if (error.response?.status === 429) {
          throw new Error("Rate limit exceeded. Please try again in a few minutes.");
        } else {
          throw new Error(`Error checking URL: ${error.message}`);
        }
      }
    },
    onSuccess: (data) => {
      setError(null);
      setCheckResult(data);
      
      // Add to history
      const historyItem: UrlCheckResult = {
        id: Date.now(),
        url: data.url,
        isSafe: data.isSafe,
        result: data.result,
        checkedAt: new Date().toISOString()
      };
      
      // Update state and localStorage
      const newHistory = [historyItem, ...urlHistory].slice(0, 10);
      setUrlHistory(newHistory);
      addToHistory(STORAGE_KEYS.URL_HISTORY, historyItem);
    },
    onError: (error: Error) => {
      setError(error.message);
      setCheckResult(null);
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) return;

    checkUrlMutation.mutate(url);
  };

  // Format history items for CollapsibleHistory component
  const historyItems: HistoryItem[] = urlHistory.map(item => ({
    id: item.id,
    title: item.url,
    subtitle: item.isSafe ? "Safe - No threats detected" : `Dangerous - ${item.result}`,
    timestamp: item.checkedAt,
    status: item.isSafe ? "safe" as const : "unsafe" as const
  }));

  return (
    <Card className="bg-white dark:bg-gray-800">
      <CardContent className="p-6">
        <h2 className="text-xl font-semibold mb-4 text-gray-800 dark:text-white">URL Checker</h2>

        <form onSubmit={handleSubmit} className="mb-4">
          <div className="mb-4">
            <Label htmlFor="url-input" className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
              Enter URL to check
            </Label>
            <div className="flex">
              <Input
                id="url-input"
                type="text"
                value={url}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="rounded-r-none bg-white dark:bg-gray-700 outline-none  focus:outline-none focus:ring-0 focus-visible:outline-none focus-visible:ring-0"
              />
              <Button 
                type="submit" 
                className="rounded-l-none"
                disabled={checkUrlMutation.isPending}
              >
                {checkUrlMutation.isPending ? "Checking..." : "Check"}
              </Button>
            </div>
          </div>
        </form>

        {/* Result Display */}
        {checkUrlMutation.isPending && (
          <div className="mb-6 p-4 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-center p-2">
              <div className="animate-spin h-5 w-5 border-2 border-blue-500 rounded-full border-t-transparent"></div>
              <span className="ml-2 text-gray-700 dark:text-gray-300">Checking URL...</span>
            </div>
          </div>
        )}

        {!checkUrlMutation.isPending && error && (
          <div className="mb-6 p-4 rounded-lg border border-red-500 bg-red-50 dark:bg-red-900/20">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800 dark:text-red-300">Error</h3>
                <div className="mt-2 text-sm text-red-700 dark:text-red-400">
                  <p>{error}</p>
                  <p className="mt-1">Please try again with a properly formatted URL (e.g., https://example.com).</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {!checkUrlMutation.isPending && checkResult && (
          <div className={`mb-6 p-4 rounded-lg border ${
            checkResult.isSafe ? "border-green-500" : "border-red-500"
          }`}>
            <div className="flex">
              <div className="flex-shrink-0">
                <span className={`inline-flex items-center justify-center h-8 w-8 rounded-full ${
                  checkResult.isSafe ? "bg-green-100 dark:bg-green-900" : "bg-red-100 dark:bg-red-900"
                }`}>
                  {checkResult.isSafe ? (
                    <svg className="h-5 w-5 text-green-500 dark:text-green-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <svg className="h-5 w-5 text-red-500 dark:text-red-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                  )}
                </span>
              </div>
              <div className="ml-3">
                <h3 className={`text-sm font-medium ${
                  checkResult.isSafe ? "text-green-800 dark:text-green-300" : "text-red-800 dark:text-red-300"
                }`}>
                  {checkResult.isSafe ? "Safe URL" : "Dangerous URL"}
                </h3>
                <div className={`mt-2 text-sm ${
                  checkResult.isSafe ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"
                }`}>
                  <p>
                    {checkResult.isSafe 
                      ? `No malicious content or suspicious patterns detected in ${checkResult.url}`
                      : `This URL shows signs of being malicious or compromised. Do not proceed to ${checkResult.url}`
                    }
                  </p>
                  {!checkResult.isSafe && checkResult.result && (
                    <p className="mt-1">Detected issues: {checkResult.result}</p>
                  )}
                </div>

                {/* SSL Certificate Warning */}
                {checkResult.hasSslIssues && (
                  <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-400 dark:border-yellow-700 rounded-md">
                    <div className="flex">
                      <div className="flex-shrink-0">
                        <svg className="h-5 w-5 text-yellow-400 dark:text-yellow-300" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                      </div>
                      <div className="ml-3">
                        <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-300">SSL Certificate Warning</h3>
                        <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-400">
                          <p>⚠️ Potential SSL Issue: The website's security certificate may be expired, misconfigured, or untrusted. Proceed with caution.</p>
                          {checkResult.sslIssues && checkResult.sslIssues.length > 0 && (
                            <ul className="mt-2 list-disc list-inside">
                              {checkResult.sslIssues.map((issue, index) => (
                                <li key={index}>{issue}</li>
                              ))}
                            </ul>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

              </div>
            </div>
          </div>
        )}

        {/* URL History */}
        <CollapsibleHistory 
          title="URL History" 
          items={historyItems}
        />
      </CardContent>
    </Card>
  );
}