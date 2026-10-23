"use client";

import { useEffect, useState, type RefObject } from "react";

export function useAnimationActivity(ref: RefObject<HTMLElement | null>) {
  const [activity, setActivity] = useState({
    visible: false,
    compact: false,
    reducedMotion: false,
  });

  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const compact = window.matchMedia("(pointer: coarse)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    let inView = false;
    const update = () => {
      const next = {
        visible: inView && !document.hidden,
        compact: compact.matches,
        reducedMotion: reducedMotion.matches,
      };
      setActivity((current) =>
        current.visible === next.visible &&
        current.compact === next.compact &&
        current.reducedMotion === next.reducedMotion
          ? current
          : next,
      );
    };
    const observer = new IntersectionObserver(([entry]) => {
      inView = entry.isIntersecting;
      update();
    });
    observer.observe(element);
    compact.addEventListener("change", update);
    reducedMotion.addEventListener("change", update);
    document.addEventListener("visibilitychange", update);
    update();
    return () => {
      observer.disconnect();
      compact.removeEventListener("change", update);
      reducedMotion.removeEventListener("change", update);
      document.removeEventListener("visibilitychange", update);
    };
  }, [ref]);

  return activity;
}
