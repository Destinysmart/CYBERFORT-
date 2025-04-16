import { useContext } from "react";
import { useTheme as useNextTheme } from "next-themes";

export function useTheme() {
  const { theme, setTheme } = useNextTheme();
  
  const toggleTheme = () => {
    setTheme(theme === "light" ? "dark" : "light");
  };
  
  return { theme, toggleTheme };
}
