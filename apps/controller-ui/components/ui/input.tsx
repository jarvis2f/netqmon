"use client";

import * as React from "react";
import {
  AnimatePresence,
  animate,
  motion,
  useReducedMotion,
} from "motion/react";

import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string | boolean;
  reserveErrorLine?: boolean;
  success?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  classNames?: {
    root?: string;
    field?: string;
    input?: string;
    label?: string;
    leftIcon?: string;
    rightIcon?: string;
    successIcon?: string;
    errorMessage?: string;
  };
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(function Input(
  {
    className,
    classNames,
    type,
    label,
    error,
    reserveErrorLine = false,
    success,
    leftIcon,
    rightIcon,
    disabled,
    id: idProp,
    onFocus,
    onBlur,
    ...props
  },
  ref,
) {
  const reactId = React.useId();
  const id = idProp ?? reactId;
  const reduce = useReducedMotion();
  const [focused, setFocused] = React.useState(false);
  const fieldRef = React.useRef<HTMLDivElement>(null);

  const isInvalid =
    props["aria-invalid"] === true || props["aria-invalid"] === "true";
  const hasError = Boolean(error) || isInvalid;
  const errorMessage = typeof error === "string" ? error : null;
  const prevHasError = React.useRef(false);

  // Shake the field when an error state appears
  React.useEffect(() => {
    if (hasError && !prevHasError.current && fieldRef.current && !reduce) {
      animate(
        fieldRef.current,
        { x: [0, -6, 6, -4, 4, -2, 0] },
        { duration: 0.42 },
      );
    }
    prevHasError.current = hasError;
  }, [hasError, reduce]);

  const rightSlot = success ? null : rightIcon;

  return (
    <div className={cn("flex flex-col gap-1.5", classNames?.root)}>
      {label ? (
        <label
          htmlFor={id}
          className={cn(
            "px-0.5 text-xs font-medium text-foreground",
            classNames?.label,
          )}
        >
          {label}
        </label>
      ) : null}

      <motion.div
        ref={fieldRef}
        data-slot="input-container"
        data-state={
          hasError
            ? "error"
            : success
              ? "success"
              : focused
                ? "focused"
                : "idle"
        }
        className={cn(
          "relative flex h-8 w-full min-w-0 items-center rounded-md border border-border bg-surface text-xs transition-colors duration-200 outline-none",
          focused && !hasError && "border-accent ring-1 ring-accent",
          hasError &&
            "border-destructive ring-1 ring-destructive/25 dark:border-destructive/50 dark:ring-destructive/40",
          disabled &&
            "cursor-not-allowed bg-surface-subtle opacity-50 pointer-events-none",
          className,
          classNames?.field,
        )}
      >
        {leftIcon ? (
          <span
            className={cn(
              "pointer-events-none absolute left-2.5 flex items-center text-foreground-muted [&_svg]:size-3.5",
              classNames?.leftIcon,
            )}
          >
            {leftIcon}
          </span>
        ) : null}

        <input
          ref={ref}
          id={id}
          type={type}
          disabled={disabled}
          data-slot="input"
          aria-invalid={hasError || undefined}
          aria-describedby={errorMessage ? `${id}-error` : undefined}
          onFocus={(event) => {
            setFocused(true);
            onFocus?.(event);
          }}
          onBlur={(event) => {
            setFocused(false);
            onBlur?.(event);
          }}
          className={cn(
            "h-full w-full min-w-0 bg-transparent px-2.5 py-1 text-xs text-foreground placeholder:text-foreground-muted outline-none",
            leftIcon && "pl-8",
            (rightSlot || success) && "pr-8",
            disabled && "cursor-not-allowed",
            classNames?.input,
          )}
          {...props}
        />

        {success ? (
          <motion.svg
            viewBox="0 0 24 24"
            fill="none"
            className={cn(
              "pointer-events-none absolute right-2.5 size-3.5 text-success",
              classNames?.successIcon,
            )}
          >
            <motion.path
              d="M5 12.5l4.5 4.5L19 7.5"
              stroke="currentColor"
              strokeWidth={2.5}
              strokeLinecap="round"
              strokeLinejoin="round"
              initial={reduce ? { pathLength: 1 } : { pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.35, ease: "easeOut" }}
            />
          </motion.svg>
        ) : rightSlot ? (
          <span
            className={cn(
              "absolute right-2.5 flex items-center text-foreground-muted [&_svg]:size-3.5",
              classNames?.rightIcon,
            )}
          >
            {rightSlot}
          </span>
        ) : null}
      </motion.div>

      <div className={reserveErrorLine ? "min-h-4" : "contents"}>
        <AnimatePresence initial={false}>
          {errorMessage ? (
            <motion.p
              id={`${id}-error`}
              role="alert"
              initial={
                reduce
                  ? { opacity: 0 }
                  : { opacity: 0, y: -4, filter: "blur(4px)" }
              }
              animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              exit={
                reduce
                  ? { opacity: 0 }
                  : { opacity: 0, y: -4, filter: "blur(4px)" }
              }
              transition={{ duration: 0.2 }}
              className={cn(
                "px-0.5 text-xs text-destructive",
                classNames?.errorMessage,
              )}
            >
              {errorMessage}
            </motion.p>
          ) : null}
        </AnimatePresence>
      </div>
    </div>
  );
});
Input.displayName = "Input";

export { Input };
