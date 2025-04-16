import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "./contexts/ThemeContext";
import { CheckHistoryProvider } from "./contexts/CheckHistoryContext";

createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
    <CheckHistoryProvider>
      <App />
    </CheckHistoryProvider>
  </ThemeProvider>
);
