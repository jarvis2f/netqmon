import React from "react";
import { AlertCircle } from "lucide-react";
import { cn } from "@/lib/utils";

interface PageContainerProps {
  children: React.ReactNode;
  toolbar?: React.ReactNode;
  warningBanner?: string | React.ReactNode;
  className?: string;
}

export function PageContainer({
  children,
  toolbar,
  warningBanner,
  className,
}: PageContainerProps) {
  return (
    <div
      className={cn("w-full flex flex-col min-h-[calc(100vh-52px)]", className)}
    >
      {/* Optional Top Warning Banner (Data Integrity / Capture Degraded, Section 77) */}
      {warningBanner && (
        <div className="w-full bg-warning-soft border-b border-warning/30 px-4 lg:px-6 py-2 flex items-center gap-2 text-xs text-warning">
          <AlertCircle className="size-4 shrink-0 text-warning" />
          <div className="flex-1">{warningBanner}</div>
        </div>
      )}

      {/* Optional Page-level Query/Filter Toolbar */}
      {toolbar && (
        <div className="w-full border-b border-border bg-surface/50 px-3 md:px-5 2xl:px-6 py-2.5 shrink-0 overflow-x-auto">
          {toolbar}
        </div>
      )}

      {/* Main Content Area */}
      <main className="flex-1 w-full px-3 md:px-5 2xl:px-6 py-5 space-y-4">
        {children}
      </main>
    </div>
  );
}
