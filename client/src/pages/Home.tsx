import { useState } from "react";
import Header from "@/components/Header";
import Footer from "@/components/Footer";
import URLChecker from "@/components/URLChecker";
import PhoneChecker from "@/components/PhoneChecker";
import { useMobile } from "@/hooks/use-mobile";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export default function Home() {
  const { isMobile } = useMobile();
  const [activeTab, setActiveTab] = useState("url");

  return (
    <div className="min-h-screen flex flex-col bg-gray-50 dark:bg-gray-900 transition-colors duration-200">
      <Header />
      
      <main className="flex-grow container mx-auto px-4 py-6">
        {isMobile ? (
          // Mobile view - tabs for switching between tools
          <Tabs defaultValue="url" onValueChange={setActiveTab} className="mb-6">
            <TabsList className="w-full grid grid-cols-2">
              <TabsTrigger value="url">URL Checker</TabsTrigger>
              <TabsTrigger value="phone">Phone Checker</TabsTrigger>
            </TabsList>
            <TabsContent value="url" className="mt-4">
              <URLChecker />
            </TabsContent>
            <TabsContent value="phone" className="mt-4">
              <PhoneChecker />
            </TabsContent>
          </Tabs>
        ) : (
          // Desktop view - side-by-side tools
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <URLChecker />
            <PhoneChecker />
          </div>
        )}
      </main>
      
      <Footer />
    </div>
  );
}
