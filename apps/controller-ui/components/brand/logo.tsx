import React from "react";
import { cn } from "@/lib/utils";

interface NetqmonLogoProps extends React.SVGProps<SVGSVGElement> {
  className?: string;
  size?: number | string;
}

export function NetqmonLogo({
  className,
  size = 32,
  ...props
}: NetqmonLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      role="img"
      aria-label="netqmon"
      className={cn("shrink-0 select-none", className)}
      {...props}
    >
      <defs>
        <linearGradient id="netqmon-grad-main" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2D8CFF" />
          <stop offset="1" stopColor="#3478F6" />
        </linearGradient>
        <linearGradient id="netqmon-grad-top" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#4BB8FF" />
          <stop offset="1" stopColor="#3294F5" />
        </linearGradient>
        <linearGradient id="netqmon-grad-bottom" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#2E86FA" />
          <stop offset="1" stopColor="#256BE8" />
        </linearGradient>
      </defs>

      <g transform="rotate(45 32 32)">
        <rect
          x="8"
          y="24"
          width="48"
          height="16"
          rx="8"
          fill="url(#netqmon-grad-main)"
        />
        <rect
          x="34"
          y="7"
          width="24"
          height="14"
          rx="7"
          fill="url(#netqmon-grad-top)"
        />
        <rect
          x="6"
          y="43"
          width="24"
          height="14"
          rx="7"
          fill="url(#netqmon-grad-bottom)"
        />
      </g>
    </svg>
  );
}

export function NetqmonBrandText({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "font-bold text-[17px] tracking-tight bg-gradient-to-r from-slate-900 via-blue-600 to-sky-500 bg-clip-text text-transparent dark:from-white dark:via-blue-400 dark:to-sky-400 select-none",
        className,
      )}
    >
      netqmon
    </span>
  );
}
