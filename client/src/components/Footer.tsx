export default function Footer() {
  return (
    <footer className="bg-white dark:bg-gray-800 py-4 shadow-inner">
      <div className="container mx-auto px-4 text-center">
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
          CyberFort analyzes URLs and phone numbers for potential threats using VirusTotal and AbstractAPI. While helpful, always exercise caution with unfamiliar websites and phone numbers.
        </p>
        <p className="text-sm text-gray-500 dark:text-gray-500">
          Created by <a href="https://twitter.com/Destinysmart_" className="text-blue-500 hover:underline" target="_blank" rel="noopener noreferrer">Destiny</a> · <a href="https://x.com/Destinysmart_" className="text-blue-500 hover:underline" target="_blank" rel="noopener noreferrer">https://x.com/Destinysmart_</a>
        </p>
      </div>
    </footer>
  );
}
