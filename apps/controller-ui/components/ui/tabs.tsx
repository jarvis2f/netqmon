"use client";

import * as React from "react";
import {
  motion,
  MotionConfig,
  useReducedMotion,
  type Transition,
} from "motion/react";
import { EASE_OUT, SPRING_PRESS } from "@/lib/ease";
import { cn } from "@/lib/utils";

export type TabVariant = "pill" | "underline" | "segment";

interface TabsContextValue {
  value: string;
  setValue: (val: string) => void;
  layoutId: string;
  variant: TabVariant;
  reduce: boolean;
}

const TabsContext = React.createContext<TabsContextValue | null>(null);

function useTabs() {
  const ctx = React.useContext(TabsContext);
  if (!ctx)
    throw new Error("Tabs compound components must be used inside <Tabs>");
  return ctx;
}

const SPRING_TAB_TRANSITION: Transition = {
  type: "spring",
  stiffness: 280,
  damping: 28,
  mass: 0.8,
};

export interface TabsProps {
  defaultValue?: string;
  value?: string;
  onValueChange?: (val: string) => void;
  variant?: TabVariant;
  children: React.ReactNode;
  className?: string;
}

export function Tabs({
  defaultValue,
  value: valueProp,
  onValueChange,
  variant = "pill",
  children,
  className,
}: TabsProps) {
  const [internalValue, setInternalValue] = React.useState(defaultValue ?? "");
  const isControlled = valueProp !== undefined;
  const currentValue = isControlled ? valueProp : internalValue;
  const layoutId = React.useId();
  const reduce = useReducedMotion();

  const setValue = React.useCallback(
    (next: string) => {
      if (!isControlled) setInternalValue(next);
      onValueChange?.(next);
    },
    [isControlled, onValueChange],
  );

  const contextValue = React.useMemo(
    () => ({
      value: currentValue,
      setValue,
      layoutId,
      variant,
      reduce: Boolean(reduce),
    }),
    [currentValue, setValue, layoutId, variant, reduce],
  );

  return (
    <MotionConfig transition={reduce ? { duration: 0 } : SPRING_TAB_TRANSITION}>
      <TabsContext.Provider value={contextValue}>
        <div data-slot="tabs" className={cn("w-full", className)}>
          {children}
        </div>
      </TabsContext.Provider>
    </MotionConfig>
  );
}

const listVariantClasses: Record<TabVariant, string> = {
  pill: "inline-flex items-center gap-1 rounded-lg bg-surface-subtle p-1 border border-border/60",
  underline: "inline-flex items-center gap-2 border-b border-border",
  segment:
    "inline-flex items-center gap-0.5 rounded-lg bg-surface-subtle p-0.5 border border-border/60",
};

export type TabsListProps = React.HTMLAttributes<HTMLDivElement>;

export function TabsList({ children, className, ...props }: TabsListProps) {
  const { variant } = useTabs();
  return (
    <div
      role="tablist"
      data-slot="tabs-list"
      className={cn(listVariantClasses[variant], className)}
      {...props}
    >
      {children}
    </div>
  );
}

type ConflictingMotionProps =
  "onAnimationStart" | "onDrag" | "onDragStart" | "onDragEnd";

export interface TabsTriggerProps extends Omit<
  React.ButtonHTMLAttributes<HTMLButtonElement>,
  ConflictingMotionProps
> {
  value: string;
  children: React.ReactNode;
  className?: string;
  disabled?: boolean;
  indicatorClassName?: string;
}

export const TabsTrigger = React.forwardRef<
  HTMLButtonElement,
  TabsTriggerProps
>(function TabsTrigger(
  {
    value,
    children,
    className,
    disabled = false,
    indicatorClassName,
    onClick,
    ...props
  },
  ref,
) {
  const {
    value: currentValue,
    setValue,
    layoutId,
    variant,
    reduce,
  } = useTabs();
  const isActive = currentValue === value;

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    setValue(value);
    onClick?.(e);
  };

  if (variant === "underline") {
    return (
      <button
        ref={ref}
        type="button"
        role="tab"
        aria-selected={isActive}
        disabled={disabled}
        data-slot="tabs-trigger"
        onClick={handleClick}
        className={cn(
          "relative isolate inline-flex min-h-8 items-center px-3 pb-2 pt-1 text-xs font-medium transition-colors outline-none cursor-pointer",
          isActive
            ? "text-foreground font-semibold"
            : "text-foreground-secondary hover:text-foreground",
          disabled && "cursor-not-allowed opacity-50",
          className,
        )}
        {...props}
      >
        <span className="relative z-10 inline-flex items-center gap-1.5">
          {children}
        </span>
        {isActive ? (
          <motion.span
            layoutId={`${layoutId}-underline`}
            transition={reduce ? { duration: 0 } : SPRING_TAB_TRANSITION}
            className={cn(
              "absolute -bottom-px left-0 right-0 h-0.5 bg-accent",
              indicatorClassName,
            )}
          />
        ) : null}
      </button>
    );
  }

  const radius = variant === "pill" ? "rounded-md" : "rounded-md";

  return (
    <motion.button
      ref={ref}
      type="button"
      role="tab"
      aria-selected={isActive}
      disabled={disabled}
      data-slot="tabs-trigger"
      onClick={handleClick}
      whileTap={reduce || disabled ? undefined : { scale: 0.97 }}
      transition={SPRING_PRESS}
      className={cn(
        "relative isolate inline-flex items-center justify-center whitespace-nowrap px-3 py-1.5 text-xs font-medium outline-none transition-colors cursor-pointer",
        isActive
          ? "text-white font-medium"
          : "text-foreground-secondary hover:text-foreground hover:bg-surface-hover/60",
        radius,
        disabled && "cursor-not-allowed opacity-50",
        className,
      )}
      {...props}
    >
      {isActive ? (
        <motion.span
          layoutId={`${layoutId}-pill`}
          transition={reduce ? { duration: 0 } : SPRING_TAB_TRANSITION}
          className={cn(
            "absolute inset-0 bg-accent shadow-2xs -z-10 pointer-events-none",
            radius,
            indicatorClassName,
          )}
        />
      ) : null}
      <span className="relative z-10 inline-flex items-center gap-1.5">
        {children}
      </span>
    </motion.button>
  );
});
TabsTrigger.displayName = "TabsTrigger";

export interface TabsContentProps {
  value: string;
  children: React.ReactNode;
  className?: string;
}

export function TabsContent({ value, children, className }: TabsContentProps) {
  const { value: currentValue, reduce } = useTabs();
  const isActive = currentValue === value;

  if (!isActive) {
    return (
      <div hidden data-slot="tabs-content" className={className}>
        {children}
      </div>
    );
  }

  return (
    <motion.div
      key={value}
      data-slot="tabs-content"
      role="tabpanel"
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 3 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.18, ease: EASE_OUT }}
      className={cn("mt-3 outline-none", className)}
    >
      {children}
    </motion.div>
  );
}
