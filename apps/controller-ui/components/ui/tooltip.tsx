"use client";

import * as React from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";

import { EASE_OUT } from "@/lib/ease";
import { cn } from "@/lib/utils";

type Side = "top" | "right" | "bottom" | "left";
type Align = "start" | "center" | "end";

const emptySubscribe = () => () => {};
function useMounted() {
  return React.useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false,
  );
}

interface TooltipContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
  side: Side;
  setSide: (side: Side) => void;
  align: Align;
  setAlign: (align: Align) => void;
  triggerRect: DOMRect | null;
  setTriggerRect: (rect: DOMRect | null) => void;
  delay: number;
}

const TooltipContext = React.createContext<TooltipContextValue | null>(null);

interface TooltipProviderProps {
  delay?: number;
  children: React.ReactNode;
}

function TooltipProvider({ children }: TooltipProviderProps) {
  return <>{children}</>;
}

interface TooltipRootProps {
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  delay?: number;
  children: React.ReactNode;
}

function Tooltip({
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  delay = 120,
  children,
}: TooltipRootProps) {
  const [uncontrolledOpen, setUncontrolledOpen] = React.useState(defaultOpen);
  const isControlled = openProp !== undefined;
  const open = isControlled ? openProp : uncontrolledOpen;

  const [side, setSide] = React.useState<Side>("top");
  const [align, setAlign] = React.useState<Align>("center");
  const [triggerRect, setTriggerRect] = React.useState<DOMRect | null>(null);

  const setOpen = React.useCallback(
    (next: boolean) => {
      if (!isControlled) setUncontrolledOpen(next);
      onOpenChange?.(next);
    },
    [isControlled, onOpenChange],
  );

  const value = React.useMemo(
    () => ({
      open,
      setOpen,
      side,
      setSide,
      align,
      setAlign,
      triggerRect,
      setTriggerRect,
      delay,
    }),
    [open, setOpen, side, align, triggerRect, delay],
  );

  return (
    <TooltipContext.Provider value={value}>{children}</TooltipContext.Provider>
  );
}

interface TooltipTriggerProps {
  render?: React.ReactElement<React.HTMLAttributes<HTMLElement>>;
  children?: React.ReactNode;
  asChild?: boolean;
}

function TooltipTrigger({ render, children }: TooltipTriggerProps) {
  const ctx = React.useContext(TooltipContext);
  const timerRef = React.useRef<NodeJS.Timeout | null>(null);
  const element =
    render ??
    (React.isValidElement<React.HTMLAttributes<HTMLElement>>(children) ? (
      children
    ) : (
      <span>{children}</span>
    ));

  const handleMouseEnter = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    ctx?.setTriggerRect(rect);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      ctx?.setOpen(true);
    }, ctx?.delay ?? 120);
    element.props.onMouseEnter?.(e);
  };

  const handleMouseLeave = (e: React.MouseEvent<HTMLElement>) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    ctx?.setOpen(false);
    element.props.onMouseLeave?.(e);
  };

  const handleFocus = (e: React.FocusEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    ctx?.setTriggerRect(rect);
    ctx?.setOpen(true);
    element.props.onFocus?.(e);
  };

  const handleBlur = (e: React.FocusEvent<HTMLElement>) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    ctx?.setOpen(false);
    element.props.onBlur?.(e);
  };

  return React.cloneElement(element, {
    onMouseEnter: handleMouseEnter,
    onMouseLeave: handleMouseLeave,
    onFocus: handleFocus,
    onBlur: handleBlur,
    "data-slot": "tooltip-trigger",
  });
}

interface TooltipContentProps {
  className?: string;
  side?: Side;
  sideOffset?: number;
  align?: Align;
  children: React.ReactNode;
}

function TooltipContent({
  className,
  side = "top",
  sideOffset = 6,
  align = "center",
  children,
}: TooltipContentProps) {
  const ctx = React.useContext(TooltipContext);
  const reduce = useReducedMotion();
  const contentRef = React.useRef<HTMLDivElement>(null);
  const mounted = useMounted();
  const [coords, setCoords] = React.useState<{ top: number; left: number }>({
    top: 0,
    left: 0,
  });

  React.useLayoutEffect(() => {
    if (!ctx?.open || !ctx.triggerRect) return;
    const rect = ctx.triggerRect;
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;
    const contentW = contentRef.current?.offsetWidth || 0;
    const contentH = contentRef.current?.offsetHeight || 0;

    let top = rect.top + scrollY;
    let left = rect.left + scrollX;

    if (side === "top") {
      top = rect.top + scrollY - contentH - sideOffset;
    } else if (side === "bottom") {
      top = rect.bottom + scrollY + sideOffset;
    } else if (side === "left") {
      left = rect.left + scrollX - contentW - sideOffset;
      top = rect.top + scrollY + (rect.height - contentH) / 2;
    } else if (side === "right") {
      left = rect.right + scrollX + sideOffset;
      top = rect.top + scrollY + (rect.height - contentH) / 2;
    }

    if (side === "top" || side === "bottom") {
      if (align === "center") {
        left = rect.left + scrollX + (rect.width - contentW) / 2;
      } else if (align === "end") {
        left = rect.right + scrollX - contentW;
      }
    }

    setCoords({
      top: Math.max(4, top),
      left: Math.max(4, left),
    });
  }, [ctx?.open, ctx?.triggerRect, side, align, sideOffset]);

  if (!mounted) return null;

  return createPortal(
    <AnimatePresence>
      {ctx?.open ? (
        <motion.div
          ref={contentRef}
          role="tooltip"
          data-slot="tooltip-content"
          initial={
            reduce
              ? { opacity: 0 }
              : {
                  opacity: 0,
                  scale: 0.94,
                  filter: "blur(3px)",
                  y: side === "top" ? 3 : side === "bottom" ? -3 : 0,
                  x: side === "left" ? 3 : side === "right" ? -3 : 0,
                }
          }
          animate={{ opacity: 1, scale: 1, filter: "blur(0px)", x: 0, y: 0 }}
          exit={
            reduce
              ? { opacity: 0 }
              : {
                  opacity: 0,
                  scale: 0.94,
                  filter: "blur(3px)",
                  y: side === "top" ? 2 : side === "bottom" ? -2 : 0,
                }
          }
          transition={{ duration: 0.15, ease: EASE_OUT }}
          style={{
            position: "absolute",
            top: coords.top,
            left: coords.left,
            zIndex: 9999,
          }}
          className={cn(
            "pointer-events-none z-50 inline-flex w-fit max-w-xs origin-center items-center gap-1.5 rounded-md bg-foreground px-2.5 py-1 text-[11px] font-medium text-background shadow-md",
            className,
          )}
        >
          {children}
        </motion.div>
      ) : null}
    </AnimatePresence>,
    document.body,
  );
}

function SimpleTooltip({
  content,
  children,
  side = "top",
  align = "center",
}: {
  content: React.ReactNode;
  children: React.ReactElement<React.HTMLAttributes<HTMLElement>>;
  side?: Side;
  align?: Align;
}) {
  if (!content) return children;
  return (
    <Tooltip>
      <TooltipTrigger render={children} />
      <TooltipContent side={side} align={align}>
        {content}
      </TooltipContent>
    </Tooltip>
  );
}

export {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
  SimpleTooltip,
};
