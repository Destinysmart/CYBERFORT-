import ThemeToggle from "./ThemeToggle";

export default function Header() {
  return (
    <header className="bg-white dark:bg-gray-800 shadow-sm">
      <div className="container mx-auto px-4 py-4 flex justify-between items-center">
        <h1 className="text-xl md:text-2xl font-semibold text-gray-800 dark:text-white">
          Cyber Awareness Tools
        </h1>
        <ThemeToggle />
      </div>
    </header>
  );
}
