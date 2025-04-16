import ThemeToggle from "./ThemeToggle";

export default function Header() {
  return (
    <header className="bg-white dark:bg-gray-800 shadow-sm">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <div className="flex items-center">
          <img 
            src="/public/cyberfort-logo.svg" 
            alt="CyberFort Logo" 
            className="h-10 w-10 mr-3" 
          />
          <div>
            <h1 className="text-xl md:text-2xl font-semibold text-gray-800 dark:text-white flex items-center">
              CyberFort
            </h1>
            <p className="text-xs md:text-sm text-gray-600 dark:text-gray-400">
              Your next level cyber awareness tool
            </p>
          </div>
        </div>
        <ThemeToggle />
      </div>
    </header>
  );
}
