"use client";

import * as React from "react";
import {
  AnimatePresence,
  motion,
  useReducedMotion,
  type HTMLMotionProps,
} from "motion/react";
import { cva, type VariantProps } from "class-variance-authority";

import { EASE_OUT, SPRING_PRESS } from "@/lib/ease";
import { useHoverCapable } from "@/lib/hooks/use-hover-capable";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "group/button relative inline-flex shrink-0 items-center justify-center cursor-pointer rounded-lg border border-transparent bg-clip-padding text-sm font-medium whitespace-nowrap transition-colors outline-none select-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 aria-invalid:border-destructive aria-invalid:ring-3 aria-invalid:ring-destructive/20 dark:aria-invalid:border-destructive/50 dark:aria-invalid:ring-destructive/40 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground hover:bg-primary/85",
        outline:
          "border-border bg-background hover:bg-muted hover:text-foreground aria-expanded:bg-muted aria-expanded:text-foreground dark:border-input dark:bg-input/30 dark:hover:bg-input/50",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-[color-mix(in_oklch,var(--secondary),var(--foreground)_5%)] aria-expanded:bg-secondary aria-expanded:text-secondary-foreground",
        ghost:
          "hover:bg-muted hover:text-foreground aria-expanded:bg-muted aria-expanded:text-foreground dark:hover:bg-muted/50",
        destructive:
          "bg-destructive/10 text-destructive hover:bg-destructive/20 focus-visible:border-destructive/40 focus-visible:ring-destructive/20 dark:bg-destructive/20 dark:hover:bg-destructive/30 dark:focus-visible:ring-destructive/40",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default:
          "h-8 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        xs: "h-6 gap-1 rounded-[min(var(--radius-md),10px)] px-2 text-xs in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-7 gap-1 rounded-[min(var(--radius-md),12px)] px-2.5 text-[0.8rem] in-data-[slot=button-group]:rounded-lg has-data-[icon=inline-end]:pr-1.5 has-data-[icon=inline-start]:pl-1.5 [&_svg:not([class*='size-'])]:size-3.5",
        lg: "h-9 gap-1.5 px-2.5 has-data-[icon=inline-end]:pr-2 has-data-[icon=inline-start]:pl-2",
        icon: "size-8",
        "icon-xs":
          "size-6 rounded-[min(var(--radius-md),10px)] in-data-[slot=button-group]:rounded-lg [&_svg:not([class*='size-'])]:size-3",
        "icon-sm":
          "size-7 rounded-[min(var(--radius-md),12px)] in-data-[slot=button-group]:rounded-lg",
        "icon-lg": "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

type Ripple = { id: number; x: number; y: number; size: number };

type ConflictingMotionProps =
  "onAnimationStart" | "onDrag" | "onDragStart" | "onDragEnd";

export interface ButtonProps
  extends
    Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, ConflictingMotionProps>,
    VariantProps<typeof buttonVariants> {
  pressScale?: number;
  hoverScale?: number;
  ripple?: boolean;
  whileTap?: HTMLMotionProps<"button">["whileTap"];
  whileHover?: HTMLMotionProps<"button">["whileHover"];
  transition?: HTMLMotionProps<"button">["transition"];
}

export interface ButtonLinkProps
  extends
    Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, ConflictingMotionProps>,
    VariantProps<typeof buttonVariants> {
  pressScale?: number;
  hoverScale?: number;
  whileTap?: HTMLMotionProps<"a">["whileTap"];
  whileHover?: HTMLMotionProps<"a">["whileHover"];
  transition?: HTMLMotionProps<"a">["transition"];
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    className,
    variant = "default",
    size = "default",
    pressScale = 0.96,
    hoverScale = 1.02,
    ripple = false,
    children,
    onPointerDown,
    disabled,
    whileTap,
    whileHover,
    transition,
    type = "button",
    ...restProps
  },
  ref,
) {
  const reduce = useReducedMotion();
  const canHover = useHoverCapable();
  const [ripples, setRipples] = React.useState<Ripple[]>([]);
  const nextId = React.useRef(0);

  const handlePointerDown = React.useCallback(
    (event: React.PointerEvent<HTMLButtonElement>) => {
      if (ripple && !reduce && !disabled) {
        const rect = event.currentTarget.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height) * 2;
        const id = nextId.current++;
        setRipples((prev) => [
          ...prev,
          {
            id,
            x: event.clientX - rect.left,
            y: event.clientY - rect.top,
            size,
          },
        ]);
      }
      onPointerDown?.(event);
    },
    [ripple, reduce, disabled, onPointerDown],
  );

  const buttonMotionProps: HTMLMotionProps<"button"> = {
    ref,
    type,
    disabled,
    whileTap:
      whileTap !== undefined
        ? whileTap
        : reduce || disabled
          ? undefined
          : { scale: pressScale },
    whileHover:
      whileHover !== undefined
        ? whileHover
        : reduce || !canHover || disabled
          ? undefined
          : { scale: hoverScale },
    transition: transition ?? SPRING_PRESS,
    onPointerDown: handlePointerDown,
    className: cn(
      buttonVariants({ variant, size }),
      ripple && "overflow-hidden",
      className,
    ),
    ...(restProps as HTMLMotionProps<"button">),
  };

  return (
    <motion.button data-slot="button" {...buttonMotionProps}>
      {ripple && !reduce ? (
        <span className="pointer-events-none absolute inset-0 overflow-hidden rounded-[inherit]">
          <AnimatePresence>
            {ripples.map((r) => (
              <motion.span
                key={r.id}
                className="absolute rounded-full bg-current opacity-20"
                style={{
                  left: r.x,
                  top: r.y,
                  width: r.size,
                  height: r.size,
                  x: "-50%",
                  y: "-50%",
                }}
                initial={{ scale: 0.05, opacity: 0.25 }}
                animate={{ scale: 1, opacity: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.6, ease: EASE_OUT }}
                onAnimationComplete={() =>
                  setRipples((prev) => prev.filter((x) => x.id !== r.id))
                }
              />
            ))}
          </AnimatePresence>
        </span>
      ) : null}
      {children}
    </motion.button>
  );
});
Button.displayName = "Button";

const ButtonLink = React.forwardRef<HTMLAnchorElement, ButtonLinkProps>(
  function ButtonLink(
    {
      className,
      variant = "default",
      size = "default",
      pressScale = 0.96,
      hoverScale = 1.02,
      children,
      whileTap,
      whileHover,
      transition,
      ...restProps
    },
    ref,
  ) {
    const reduce = useReducedMotion();
    const canHover = useHoverCapable();

    const linkMotionProps: HTMLMotionProps<"a"> = {
      ref,
      whileTap:
        whileTap !== undefined
          ? whileTap
          : reduce
            ? undefined
            : { scale: pressScale },
      whileHover:
        whileHover !== undefined
          ? whileHover
          : reduce || !canHover
            ? undefined
            : { scale: hoverScale },
      transition: transition ?? SPRING_PRESS,
      className: cn(buttonVariants({ variant, size }), className),
      ...(restProps as HTMLMotionProps<"a">),
    };

    return (
      <motion.a data-slot="button" {...linkMotionProps}>
        {children}
      </motion.a>
    );
  },
);
ButtonLink.displayName = "ButtonLink";

export { Button, ButtonLink, buttonVariants };
