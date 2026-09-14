"use client";

import { useEffect, useRef, useState } from "react";
import { dashboardIcons } from "@/lib/dashboard-icons";
import {
  iconContainerClass,
  IconFallback,
  type IconSize,
} from "./icon-fallback";

export function LazyRemoteIcon({
  src,
  size = "sm",
  fallback,
}: {
  src: string;
  size?: IconSize;
  fallback?: React.ReactNode;
}) {
  const rootRef = useRef<HTMLSpanElement>(null);
  const [visible, setVisible] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const node = rootRef.current;
    if (!node || visible || failed) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry?.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { rootMargin: "100px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [failed, visible]);

  if (failed)
    return (
      fallback ?? <IconFallback icon={dashboardIcons.unknown} size={size} />
    );

  return (
    <span ref={rootRef} className={iconContainerClass(size)} aria-hidden="true">
      {visible ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={src}
          alt=""
          className="size-full object-contain"
          onError={() => setFailed(true)}
        />
      ) : (
        <dashboardIcons.loading className="size-3 animate-spin" />
      )}
    </span>
  );
}
