import { useState } from "react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { formatDistanceToNow } from "date-fns";

interface HistoryItem {
  id: number;
  title: string;
  subtitle: string;
  timestamp: string;
  status: "safe" | "unsafe";
}

interface CollapsibleHistoryProps {
  title: string;
  items: HistoryItem[];
}

export default function CollapsibleHistory({ title, items }: CollapsibleHistoryProps) {
  const [isOpen, setIsOpen] = useState(true);

  return (
    <div className="mb-4">
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <div className="flex justify-between items-center mb-2">
          <h3 className="text-lg font-medium text-gray-800 dark:text-white">{title}</h3>
          <CollapsibleTrigger asChild>
            <button className="text-sm text-blue-500 hover:text-blue-700 dark:hover:text-blue-400">
              {isOpen ? "Hide" : "Show"}
            </button>
          </CollapsibleTrigger>
        </div>
        <CollapsibleContent>
          <ScrollArea className="border border-gray-200 dark:border-gray-700 rounded-lg max-h-60">
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {items.length === 0 ? (
                <div className="p-3 bg-white dark:bg-gray-800 text-center text-gray-500 dark:text-gray-400">
                  No history yet
                </div>
              ) : (
                items.map((item) => (
                  <div key={item.id} className="p-3 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700">
                    <div className="flex items-start">
                      <div className="flex-shrink-0">
                        <span 
                          className={`inline-block w-3 h-3 rounded-full mr-2 mt-1 ${
                            item.status === "safe" ? "bg-green-500" : "bg-red-500"
                          }`}
                        ></span>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                          {item.title}
                        </p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {item.subtitle}
                        </p>
                      </div>
                      <div className="text-xs text-gray-500 dark:text-gray-400">
                        {formatTimeAgo(item.timestamp)}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}

function formatTimeAgo(timestamp: string) {
  try {
    return formatDistanceToNow(new Date(timestamp), { addSuffix: true });
  } catch (error) {
    return "just now";
  }
}
