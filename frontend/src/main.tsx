import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ConfirmProvider, ToastProvider } from "./components/ui";
import "./index.css";
import { ApiError } from "./lib/api";
import { AuthProvider } from "./lib/auth";
import { BrandingProvider } from "./lib/branding";

const qc = new QueryClient({
  defaultOptions: {
    queries: { retry: (n, e) => !(e instanceof ApiError && e.status < 500) && n < 2, refetchOnWindowFocus: false, staleTime: 10000 },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <ToastProvider>
          <ConfirmProvider>
            <BrandingProvider><AuthProvider><App /></AuthProvider></BrandingProvider>
          </ConfirmProvider>
        </ToastProvider>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
