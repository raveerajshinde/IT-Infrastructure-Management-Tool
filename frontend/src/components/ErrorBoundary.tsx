import { AlertTriangle } from "lucide-react";
import { Component, ReactNode } from "react";

/** Keeps the shell usable when one page fails to render and shows what went wrong. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error) { console.error("InfraPilot page error:", error); }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" className="rounded-lg border border-red-200 bg-red-50 p-5 text-sm text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100">
        <p className="flex items-center gap-2 font-semibold"><AlertTriangle className="h-4 w-4" />This page could not be displayed</p>
        <p className="mt-1">Other pages still work. Please report the message below.</p>
        <pre className="code mt-3 max-h-60 overflow-auto">{this.state.error.message}{"\n"}{this.state.error.stack?.split("\n").slice(0, 4).join("\n")}</pre>
        <button className="mt-3 rounded-md bg-red-600 px-3 py-1.5 text-white hover:bg-red-700" onClick={() => this.setState({ error: null })}>Try again</button>
      </div>
    );
  }
}
