import React, { createContext, useContext, useState } from "react";

export interface UrlCheckResult {
  id: number;
  url: string;
  isSafe: boolean;
  result: string;
  checkedAt: string;
}

export interface PhoneCheckResult {
  id: number;
  phoneNumber: string;
  isSafe: boolean;
  country: string;
  carrier: string;
  lineType: string;
  riskScore: number;
  checkedAt: string;
}

interface CheckHistoryContextType {
  urlHistory: UrlCheckResult[];
  phoneHistory: PhoneCheckResult[];
  setUrlHistory: React.Dispatch<React.SetStateAction<UrlCheckResult[]>>;
  setPhoneHistory: React.Dispatch<React.SetStateAction<PhoneCheckResult[]>>;
  addUrlCheck: (check: UrlCheckResult) => void;
  addPhoneCheck: (check: PhoneCheckResult) => void;
}

const CheckHistoryContext = createContext<CheckHistoryContextType | undefined>(undefined);

export function CheckHistoryProvider({ children }: { children: React.ReactNode }) {
  const [urlHistory, setUrlHistory] = useState<UrlCheckResult[]>([]);
  const [phoneHistory, setPhoneHistory] = useState<PhoneCheckResult[]>([]);

  const addUrlCheck = (check: UrlCheckResult) => {
    setUrlHistory(prev => [check, ...prev].slice(0, 10));
  };

  const addPhoneCheck = (check: PhoneCheckResult) => {
    setPhoneHistory(prev => [check, ...prev].slice(0, 10));
  };

  return (
    <CheckHistoryContext.Provider 
      value={{ 
        urlHistory, 
        phoneHistory, 
        setUrlHistory, 
        setPhoneHistory, 
        addUrlCheck,
        addPhoneCheck 
      }}
    >
      {children}
    </CheckHistoryContext.Provider>
  );
}

export function useCheckHistory() {
  const context = useContext(CheckHistoryContext);
  if (context === undefined) {
    throw new Error("useCheckHistory must be used within a CheckHistoryProvider");
  }
  return context;
}
