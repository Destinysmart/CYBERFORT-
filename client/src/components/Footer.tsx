export default function Footer() {
  return (
    <footer className="bg-white dark:bg-gray-800 py-4 shadow-inner">
      <div className="container mx-auto px-4 text-center">
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
          CyberFort helps detect threats in URLs and phone numbers using trusted services.
          Stay safe — always verify unknown links and calls.
        </p>
        <p className="text-sm text-gray-500 dark:text-gray-500">
          Made by <a href="https://x.com/Destinysmart_" className="text-blue-500 hover:underline" target="_blank" rel="noopener noreferrer">Destiny</a>
        </p>
      </div>
    </footer>
  );
}
