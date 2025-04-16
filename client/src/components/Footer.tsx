export default function Footer() {
  return (
    <footer className="bg-white dark:bg-gray-800 py-4 shadow-inner">
      <div className="container mx-auto px-4 text-center">
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
          This tool analyzes URLs for common threats and suspicious patterns. While helpful, always use caution when visiting unfamiliar websites.
        </p>
        <p className="text-sm text-gray-500 dark:text-gray-500">
          Created by Destiny · <a href="https://x.com/Destinysmart_" className="text-blue-500 hover:underline" target="_blank" rel="noopener noreferrer">https://x.com/Destinysmart_</a>
        </p>
      </div>
    </footer>
  );
}
