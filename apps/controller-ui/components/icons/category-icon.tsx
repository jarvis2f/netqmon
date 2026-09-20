"use client";

import { getCategoryIcon } from "@/lib/category-icons";
import { IconFallback, type IconSize } from "./icon-fallback";

export function CategoryIcon({
  category,
  size = "sm",
}: {
  category?: string | null;
  size?: IconSize;
}) {
  return <IconFallback icon={getCategoryIcon(category)} size={size} />;
}
