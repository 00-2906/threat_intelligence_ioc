import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider, createTheme } from "@mui/material/styles";

const darkTheme = createTheme({
  palette: { mode: "dark", primary: { main: "#4f46e5" } },
});

createRoot(document.getElementById("root")).render(
  <ThemeProvider theme={darkTheme}>
    <CssBaseline />
    <App />
  </ThemeProvider>
);
