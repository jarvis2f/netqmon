"use client";

import * as React from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";

import { cn } from "@/lib/utils";

type Side = "top" | "bottom" | "left" | "right";
type Align = "start" | "center" | "end";

const emptySubscribe = () => () => {};
function useMounted() {
  return React.useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false,
  );
}

interface PopoverContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
  triggerNode: HTMLElement | null;
  setTriggerNode: (node: HTMLElement | null) => void;
  triggerId: string;
  contentId: string;
}

const PopoverContext = React.createContext<PopoverContextValue | null>(null);

function usePopoverContext(component: string) {
  const ctx = React.useContext(PopoverContext);
  if (!ctx) throw new Error(`${component} must be used within <Popover>`);
  return ctx;
}

export interface PopoverProps {
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  children: React.ReactNode;
}

function Popover({
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  children,
}: PopoverProps) {
  const [uncontrolledOpen, setUncontrolledOpen] = React.useState(defaultOpen);
  const isControlled = openProp !== undefined;
  const open = isControlled ? openProp : uncontrolledOpen;

  const [triggerNode, setTriggerNode] = React.useState<HTMLElement | null>(
    null,
  );
  const triggerId = React.useId();
  const contentId = React.useId();

  const setOpen = React.useCallback(
    (next: boolean) => {
      if (!isControlled) setUncontrolledOpen(next);
      onOpenChange?.(next);
    },
    [isControlled, onOpenChange],
  );

  // Click outside and escape key handling
  React.useEffect(() => {
    if (!open) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };

    const handleClickOutside = (e: MouseEvent | TouchEvent) => {
      const target = e.target as HTMLElement;
      if (
        triggerNode?.contains(target) ||
        target.closest(`[id="${contentId}"]`)
      ) {
        return;
      }
      setOpen(false);
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("pointerdown", handleClickOutside);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("pointerdown", handleClickOutside);
    };
  }, [open, setOpen, triggerNode, contentId]);

  const contextValue = React.useMemo(
    () => ({
      open,
      setOpen,
      triggerNode,
      setTriggerNode,
      triggerId,
      contentId,
    }),
    [open, setOpen, triggerNode, triggerId, contentId],
  );

  return (
    <PopoverContext.Provider value={contextValue}>
      <div data-slot="popover" className="relative inline-block">
        {children}
      </div>
    </PopoverContext.Provider>
  );
}

export interface PopoverTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  render?: React.ReactElement<React.HTMLAttributes<HTMLElement>>;
  asChild?: boolean;
}

const PopoverTrigger = React.forwardRef<HTMLButtonElement, PopoverTriggerProps>(
  function PopoverTrigger(
    { render, children, className, onClick, ...props },
    ref,
  ) {
    const ctx = usePopoverContext("PopoverTrigger");
    const { setTriggerNode, triggerId, contentId, open, setOpen } = ctx;

    const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
      setOpen(!open);
      onClick?.(e);
    };

    if (render) {
      const renderProps = render.props;
      return React.cloneElement(render, {
        ref: (node: HTMLElement | null) => {
          setTriggerNode(node);
          if (typeof ref === "function") ref(node as HTMLButtonElement);
        },
        id: triggerId,
        "aria-haspopup": "dialog",
        "aria-expanded": open,
        "aria-controls": contentId,
        "data-slot": "popover-trigger",
        onClick: (e: React.MouseEvent<HTMLElement>) => {
          renderProps.onClick?.(e);
          setOpen(!open);
        },
      } as React.HTMLAttributes<HTMLElement>);
    }

    return (
      <button
        ref={(node) => {
          setTriggerNode(node);
          if (typeof ref === "function") ref(node);
        }}
        id={triggerId}
        type="button"
        data-slot="popover-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={handleClick}
        className={cn("outline-none", className)}
        {...props}
      >
        {children}
      </button>
    );
  },
);
PopoverTrigger.displayName = "PopoverTrigger";

export interface PopoverContentProps {
  className?: string;
  align?: Align;
  alignOffset?: number;
  side?: Side;
  sideOffset?: number;
  children: React.ReactNode;
}

function PopoverContent({
  className,
  align = "center",
  alignOffset = 0,
  side = "bottom",
  sideOffset = 4,
  children,
}: PopoverContentProps) {
  const ctx = usePopoverContext("PopoverContent");
  const reduce = useReducedMotion();
  const contentRef = React.useRef<HTMLDivElement>(null);
  const mounted = useMounted();
  const [coords, setCoords] = React.useState<{ top: number; left: number }>({
    top: 0,
    left: 0,
  });

  React.useLayoutEffect(() => {
    if (!ctx.open || !ctx.triggerNode) return;
    const rect = ctx.triggerNode.getBoundingClientRect();
    const contentW = contentRef.current?.offsetWidth || 288;
    const contentH = contentRef.current?.offsetHeight || 200;
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    let top = rect.bottom + scrollY + sideOffset;
    let left = rect.left + scrollX + alignOffset;

    if (side === "top") {
      top = rect.top + scrollY - contentH - sideOffset;
    } else if (side === "left") {
      left = rect.left + scrollX - contentW - sideOffset;
      top = rect.top + scrollY + alignOffset;
    } else if (side === "right") {
      left = rect.right + scrollX + sideOffset;
      top = rect.top + scrollY + alignOffset;
    }

    if (side === "top" || side === "bottom") {
      if (align === "center") {
        left = rect.left + scrollX + (rect.width - contentW) / 2 + alignOffset;
      } else if (align === "end") {
        left = rect.right + scrollX - contentW + alignOffset;
      }
    }

    setCoords({
      top: Math.max(8, top),
      left: Math.max(8, Math.min(window.innerWidth - contentW - 8, left)),
    });
  }, [ctx.open, ctx.triggerNode, side, sideOffset, align, alignOffset]);

  if (!mounted) return null;

  return createPortal(
    <AnimatePresence>
      {ctx.open ? (
        <motion.div
          ref={contentRef}
          id={ctx.contentId}
          role="dialog"
          data-slot="popover-content"
          initial={
            reduce
              ? { opacity: 0 }
              : {
                  opacity: 0,
                  scale: 0.95,
                  y: side === "bottom" ? -4 : side === "top" ? 4 : 0,
                  x: side === "right" ? -4 : side === "left" ? 4 : 0,
                  filter: "blur(2px)",
                }
          }
          animate={{
            opacity: 1,
            scale: 1,
            y: 0,
            x: 0,
            filter: "blur(0px)",
          }}
          exit={
            reduce
              ? { opacity: 0 }
              : {
                  opacity: 0,
                  scale: 0.95,
                  y: side === "bottom" ? -4 : side === "top" ? 4 : 0,
                  x: side === "right" ? -4 : side === "left" ? 4 : 0,
                  filter: "blur(2px)",
                }
          }
          transition={{
            type: "spring",
            duration: 0.3,
            bounce: 0.12,
          }}
          style={{
            position: "absolute",
            top: coords.top,
            left: coords.left,
            zIndex: 9999,
          }}
          className={cn(
            "z-50 flex w-72 flex-col gap-2.5 rounded-lg bg-popover p-2.5 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none",
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

function PopoverHeader({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="popover-header"
      className={cn("flex flex-col gap-0.5 text-sm", className)}
      {...props}
    />
  );
}

function PopoverTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="popover-title"
      className={cn("font-medium text-foreground", className)}
      {...props}
    />
  );
}

function PopoverDescription({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="popover-description"
      className={cn("text-muted-foreground text-xs", className)}
      {...props}
    />
  );
}

export {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
};
