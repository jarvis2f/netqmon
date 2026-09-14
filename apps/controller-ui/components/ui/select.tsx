"use client";

import * as React from "react";
import { createPortal } from "react-dom";
import { Check, ChevronDown, ChevronUp } from "lucide-react";
import {
  AnimatePresence,
  motion,
  type Transition,
  useReducedMotion,
  type Variants,
} from "motion/react";

import { EASE_OUT, SPRING_PRESS } from "@/lib/ease";
import { cn } from "@/lib/utils";

const emptySubscribe = () => () => {};
function useMounted() {
  return React.useSyncExternalStore(
    emptySubscribe,
    () => true,
    () => false,
  );
}

const CHEVRON_TRANSITION: Transition = {
  type: "spring",
  duration: 0.4,
  bounce: 0.3,
};

const LIST_VARIANTS: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.03, delayChildren: 0.04 } },
};

const ITEM_VARIANTS: Variants = {
  hidden: { opacity: 0, y: -4, filter: "blur(3px)" },
  show: { opacity: 1, y: 0, filter: "blur(0px)" },
};

type Placement = "bottom" | "top";

interface SelectContextValue {
  value: string | undefined;
  open: boolean;
  setOpen: (open: boolean) => void;
  select: (value: string) => void;
  register: (value: string, label: React.ReactNode) => void;
  unregister: (value: string) => void;
  labelFor: (value: string | undefined) => React.ReactNode;
  reduce: boolean;
  triggerId: string;
  listId: string;
  disabled: boolean;
  placement: Placement;
  setPlacement: (p: Placement) => void;
  triggerRect: DOMRect | null;
  setTriggerRect: (rect: DOMRect | null) => void;
}

const SelectContext = React.createContext<SelectContextValue | null>(null);

function useSelectContext(component: string) {
  const ctx = React.useContext(SelectContext);
  if (!ctx) throw new Error(`${component} must be used within <Select>`);
  return ctx;
}

export interface SelectProps {
  value?: string;
  defaultValue?: string;
  onValueChange?: (value: string) => void;
  open?: boolean;
  defaultOpen?: boolean;
  onOpenChange?: (open: boolean) => void;
  disabled?: boolean;
  children?: React.ReactNode;
}

function Select({
  value: valueProp,
  defaultValue,
  onValueChange,
  open: openProp,
  defaultOpen = false,
  onOpenChange,
  disabled = false,
  children,
}: SelectProps) {
  const reduce = useReducedMotion();
  const triggerId = React.useId();
  const listId = React.useId();

  const [uncontrolledValue, setUncontrolledValue] = React.useState(
    defaultValue ?? "",
  );
  const isControlledValue = valueProp !== undefined;
  const value = isControlledValue ? valueProp : uncontrolledValue;

  const [uncontrolledOpen, setUncontrolledOpen] = React.useState(defaultOpen);
  const isControlledOpen = openProp !== undefined;
  const open = isControlledOpen ? openProp : uncontrolledOpen;

  const [placement, setPlacement] = React.useState<Placement>("bottom");
  const [triggerRect, setTriggerRect] = React.useState<DOMRect | null>(null);
  const labelsRef = React.useRef<Map<string, React.ReactNode>>(new Map());
  const [, forceUpdate] = React.useReducer((x) => x + 1, 0);

  const setOpen = React.useCallback(
    (next: boolean) => {
      if (!isControlledOpen) setUncontrolledOpen(next);
      onOpenChange?.(next);
    },
    [isControlledOpen, onOpenChange],
  );

  const select = React.useCallback(
    (val: string) => {
      if (!isControlledValue) setUncontrolledValue(val);
      onValueChange?.(val);
      setOpen(false);
    },
    [isControlledValue, onValueChange, setOpen],
  );

  const register = React.useCallback((val: string, label: React.ReactNode) => {
    labelsRef.current.set(val, label);
    forceUpdate();
  }, []);

  const unregister = React.useCallback((val: string) => {
    labelsRef.current.delete(val);
  }, []);

  const labelFor = React.useCallback(
    (val: string | undefined) =>
      val !== undefined ? labelsRef.current.get(val) : undefined,
    [],
  );

  // Close on Escape or click outside
  React.useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (
        !target.closest(`[aria-controls="${listId}"]`) &&
        !target.closest(`#${triggerId}`) &&
        !target.closest(`[id="${listId}"]`)
      ) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onClick);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onClick);
    };
  }, [open, setOpen, listId, triggerId]);

  const contextValue = React.useMemo<SelectContextValue>(
    () => ({
      value,
      open,
      setOpen,
      select,
      register,
      unregister,
      labelFor,
      reduce: Boolean(reduce),
      triggerId,
      listId,
      disabled,
      placement,
      setPlacement,
      triggerRect,
      setTriggerRect,
    }),
    [
      value,
      open,
      setOpen,
      select,
      register,
      unregister,
      labelFor,
      reduce,
      triggerId,
      listId,
      disabled,
      placement,
      setPlacement,
      triggerRect,
      setTriggerRect,
    ],
  );

  return (
    <SelectContext.Provider value={contextValue}>
      <div data-slot="select-root" className="relative inline-block w-fit">
        {children}
      </div>
    </SelectContext.Provider>
  );
}

type ConflictingMotionProps =
  "onAnimationStart" | "onDrag" | "onDragStart" | "onDragEnd";

export interface SelectTriggerProps extends Omit<
  React.ButtonHTMLAttributes<HTMLButtonElement>,
  "size" | ConflictingMotionProps
> {
  size?: "sm" | "default";
  children?: React.ReactNode;
}

const SelectTrigger = React.forwardRef<HTMLButtonElement, SelectTriggerProps>(
  function SelectTrigger(
    { className, size = "default", children, disabled: propDisabled, ...props },
    ref,
  ) {
    const ctx = useSelectContext("SelectTrigger");
    const triggerRef = React.useRef<HTMLButtonElement | null>(null);
    const disabled = ctx.disabled || propDisabled;

    const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
      if (disabled) return;
      if (triggerRef.current) {
        ctx.setTriggerRect(triggerRef.current.getBoundingClientRect());
      }
      ctx.setOpen(!ctx.open);
      props.onClick?.(e);
    };

    return (
      <motion.button
        ref={(node) => {
          triggerRef.current = node;
          if (typeof ref === "function") ref(node);
          else if (ref) ref.current = node;
        }}
        type="button"
        id={ctx.triggerId}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={ctx.open}
        aria-controls={ctx.listId}
        onClick={handleClick}
        whileTap={ctx.reduce || disabled ? undefined : { scale: 0.98 }}
        transition={SPRING_PRESS}
        data-slot="select-trigger"
        data-size={size}
        className={cn(
          "flex w-fit cursor-pointer items-center justify-between gap-1.5 rounded-md border border-border bg-surface px-2.5 text-xs text-foreground whitespace-nowrap transition-colors outline-none select-none hover:bg-surface-hover focus-visible:border-accent focus-visible:ring-1 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-1 aria-invalid:ring-destructive/20 data-[size=default]:h-8 data-[size=sm]:h-7 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-3.5",
          className,
        )}
        {...props}
      >
        <span className="flex flex-1 items-center gap-1.5 truncate">
          {children}
        </span>
        <motion.span
          aria-hidden
          animate={{ rotate: ctx.open ? 180 : 0 }}
          transition={ctx.reduce ? { duration: 0 } : CHEVRON_TRANSITION}
          className="text-foreground-muted ml-1 inline-flex items-center"
        >
          <ChevronDown className="size-3.5" />
        </motion.span>
      </motion.button>
    );
  },
);
SelectTrigger.displayName = "SelectTrigger";

export interface SelectValueProps {
  placeholder?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}

function SelectValue({ placeholder, className, children }: SelectValueProps) {
  const ctx = useSelectContext("SelectValue");
  const registeredLabel = ctx.labelFor(ctx.value);
  const displayContent =
    registeredLabel ?? children ?? ctx.value ?? placeholder;

  return (
    <span
      data-slot="select-value"
      className={cn(
        "flex flex-1 items-center gap-1.5 truncate text-left",
        ctx.value ? "text-foreground font-normal" : "text-foreground-muted",
        className,
      )}
    >
      {displayContent}
    </span>
  );
}

export interface SelectContentProps {
  className?: string;
  align?: "start" | "center" | "end";
  side?: "top" | "bottom";
  sideOffset?: number;
  alignOffset?: number;
  children: React.ReactNode;
}

function SelectContent({
  className,
  align = "start",
  side = "bottom",
  sideOffset = 4,
  children,
}: SelectContentProps) {
  const ctx = useSelectContext("SelectContent");
  const mounted = useMounted();
  const contentRef = React.useRef<HTMLDivElement>(null);
  const [coords, setCoords] = React.useState<{
    top: number;
    left: number;
    minWidth: number;
  }>({
    top: 0,
    left: 0,
    minWidth: 120,
  });

  // Calculate position relative to trigger
  React.useLayoutEffect(() => {
    if (!ctx.open) return;
    const trigger = document.getElementById(ctx.triggerId);
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const scrollY = window.scrollY;
    const scrollX = window.scrollX;

    const top =
      side === "top"
        ? rect.top + scrollY - sideOffset
        : rect.bottom + scrollY + sideOffset;

    let left = rect.left + scrollX;
    if (align === "end") {
      left =
        rect.right + scrollX - (contentRef.current?.offsetWidth || rect.width);
    } else if (align === "center") {
      left =
        rect.left +
        scrollX +
        (rect.width - (contentRef.current?.offsetWidth || rect.width)) / 2;
    }

    setCoords({
      top,
      left: Math.max(8, left),
      minWidth: Math.max(120, rect.width),
    });
  }, [ctx.open, ctx.triggerId, side, align, sideOffset]);

  if (!mounted) return null;

  return createPortal(
    <AnimatePresence>
      {ctx.open ? (
        <motion.div
          ref={contentRef}
          id={ctx.listId}
          role="listbox"
          data-slot="select-content"
          initial={
            ctx.reduce
              ? { opacity: 0 }
              : { opacity: 0, scale: 0.96, y: side === "top" ? 4 : -4 }
          }
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={
            ctx.reduce
              ? { opacity: 0 }
              : { opacity: 0, scale: 0.96, y: side === "top" ? 4 : -4 }
          }
          transition={{ duration: 0.16, ease: EASE_OUT }}
          style={{
            position: "absolute",
            top: coords.top,
            left: coords.left,
            minWidth: coords.minWidth,
            zIndex: 9999,
          }}
          className={cn(
            "relative isolate max-h-72 origin-top overflow-x-hidden overflow-y-auto rounded-md border border-border bg-surface p-1 text-foreground shadow-lg",
            className,
          )}
        >
          <motion.div
            variants={ctx.reduce ? undefined : LIST_VARIANTS}
            initial="hidden"
            animate="show"
            className="flex flex-col gap-0.5"
          >
            {children}
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>,
    document.body,
  );
}

export interface SelectItemProps {
  value: string;
  disabled?: boolean;
  className?: string;
  children: React.ReactNode;
}

function SelectItem({
  value,
  disabled = false,
  className,
  children,
}: SelectItemProps) {
  const ctx = useSelectContext("SelectItem");
  const selected = ctx.value === value;

  React.useEffect(() => {
    ctx.register(value, children);
    return () => ctx.unregister(value);
  }, [ctx, value, children]);

  return (
    <motion.div variants={ctx.reduce ? undefined : ITEM_VARIANTS}>
      <button
        type="button"
        role="option"
        aria-selected={selected}
        disabled={disabled}
        data-slot="select-item"
        onClick={() => ctx.select(value)}
        className={cn(
          "relative flex w-full cursor-pointer items-center justify-between gap-1.5 rounded px-2 py-1 text-xs text-foreground outline-none select-none transition-colors hover:bg-surface-hover focus:bg-surface-hover focus:text-foreground disabled:pointer-events-none disabled:opacity-50",
          selected && "bg-surface-hover font-medium text-accent",
          className,
        )}
      >
        <span className="truncate">{children}</span>
        {selected ? (
          <motion.span
            initial={ctx.reduce ? undefined : { scale: 0.5, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            className="text-accent ml-2 shrink-0"
          >
            <Check className="size-3.5" />
          </motion.span>
        ) : null}
      </button>
    </motion.div>
  );
}

function SelectGroup({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="select-group"
      className={cn("scroll-my-1 p-1", className)}
      {...props}
    />
  );
}

function SelectLabel({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="select-label"
      className={cn(
        "px-2 py-1 text-[11px] font-semibold tracking-wider text-foreground-muted uppercase",
        className,
      )}
      {...props}
    />
  );
}

function SelectSeparator({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="select-separator"
      className={cn("pointer-events-none -mx-1 my-1 h-px bg-border", className)}
      {...props}
    />
  );
}

function SelectScrollUpButton({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="select-scroll-up-button"
      className={cn(
        "top-0 z-10 flex w-full cursor-default items-center justify-center bg-surface py-1 text-foreground-muted",
        className,
      )}
      {...props}
    >
      <ChevronUp className="size-3.5" />
    </div>
  );
}

function SelectScrollDownButton({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="select-scroll-down-button"
      className={cn(
        "bottom-0 z-10 flex w-full cursor-default items-center justify-center bg-surface py-1 text-foreground-muted",
        className,
      )}
      {...props}
    >
      <ChevronDown className="size-3.5" />
    </div>
  );
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
};
