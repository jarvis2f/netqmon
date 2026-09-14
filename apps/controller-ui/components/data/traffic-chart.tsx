"use client";

import React, { useState, useMemo, useId } from "react";
import { useTranslations } from "next-intl";
import { formatBitrate, formatTimestamp } from "@/lib/formatters";
import { cn } from "@/lib/utils";

export interface TrafficDataPoint {
  timestamp: number; // epoch ms or epoch sec
  downloadBps: number;
  uploadBps: number;
  totalBps?: number;
}

interface TrafficChartProps {
  data: TrafficDataPoint[];
  title?: string;
  height?: number;
  showLegend?: boolean;
  showTotal?: boolean;
  loading?: boolean;
  className?: string;
  emptyMessage?: string;
  maxPoints?: number;
  showDownload?: boolean;
  showUpload?: boolean;
}

export function TrafficChart({
  data,
  title,
  height = 240,
  showLegend = true,
  showTotal = false,
  loading = false,
  className,
  emptyMessage,
  maxPoints = 900,
  showDownload = true,
  showUpload = true,
}: TrafficChartProps) {
  const t = useTranslations("traffic.columns");
  const tStates = useTranslations("overview");
  const gradientId = useId().replaceAll(":", "");
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [visibleSeries, setVisibleSeries] = useState({
    download: true,
    upload: true,
    total: showTotal,
  });
  const seriesVisible = {
    download: visibleSeries.download && showDownload,
    upload: visibleSeries.upload && showUpload,
    total: visibleSeries.total,
  };
  const boundedData = useMemo(
    () => data.slice(-Math.max(1, maxPoints)),
    [data, maxPoints],
  );

  // Calculate chart bounds and paths
  const chartLayout = useMemo(() => {
    if (boundedData.length === 0) return null;

    const plotWidth = 1000;
    const padding = { top: 12, right: 0, bottom: 0, left: 0 };
    const chartWidth = plotWidth;
    const chartHeight = Math.max(height - 42, 60);

    // Max value calculation
    let maxVal = 1000; // minimum scale 1 Kbps
    for (const d of boundedData) {
      if (seriesVisible.download) maxVal = Math.max(maxVal, d.downloadBps);
      if (seriesVisible.upload) maxVal = Math.max(maxVal, d.uploadBps);
      if (seriesVisible.total)
        maxVal = Math.max(maxVal, d.totalBps ?? d.downloadBps + d.uploadBps);
    }
    // Add 10% headroom
    maxVal = maxVal * 1.15;

    const numPoints = boundedData.length;
    const getX = (index: number) =>
      padding.left + (index / Math.max(numPoints - 1, 1)) * chartWidth;
    const getY = (val: number) =>
      padding.top + chartHeight - (val / maxVal) * chartHeight;

    // Generate paths
    const downloadPoints: [number, number][] = [];
    const uploadPoints: [number, number][] = [];
    const totalPoints: [number, number][] = [];

    boundedData.forEach((d, idx) => {
      const x = getX(idx);
      downloadPoints.push([x, getY(d.downloadBps)]);
      uploadPoints.push([x, getY(d.uploadBps)]);
      totalPoints.push([x, getY(d.totalBps ?? d.downloadBps + d.uploadBps)]);
    });

    const createSvgPath = (pts: [number, number][]) => {
      if (pts.length === 0) return "";
      return pts.reduce(
        (acc, [x, y], i) =>
          i === 0
            ? `M ${x.toFixed(1)} ${y.toFixed(1)}`
            : `${acc} L ${x.toFixed(1)} ${y.toFixed(1)}`,
        "",
      );
    };

    const createAreaPath = (pts: [number, number][]) => {
      if (pts.length === 0) return "";
      const baseLineY = padding.top + chartHeight;
      const firstX = pts[0][0];
      const lastX = pts[pts.length - 1][0];
      const linePath = createSvgPath(pts);
      return `${linePath} L ${lastX.toFixed(1)} ${baseLineY} L ${firstX.toFixed(1)} ${baseLineY} Z`;
    };

    // Generate 4 Y-axis ticks
    const yTicks = [0, maxVal * 0.33, maxVal * 0.66, maxVal].map((val) => ({
      val,
      y: getY(val),
      label: formatBitrate(val),
    }));

    // Generate 4-6 X-axis ticks
    const xTickCount = Math.min(
      Math.max(Math.floor(chartWidth / 100), 2),
      numPoints,
    );
    const xTicks: { index: number; x: number; label: string }[] = [];
    for (let i = 0; i < xTickCount; i++) {
      const pointIndex =
        xTickCount === 1
          ? 0
          : Math.floor((i / (xTickCount - 1)) * (numPoints - 1));
      const point = boundedData[pointIndex];
      if (point) {
        xTicks.push({
          index: pointIndex,
          x: getX(pointIndex),
          label: formatTimestamp(point.timestamp, "table"),
        });
      }
    }

    return {
      padding,
      plotWidth,
      chartWidth,
      chartHeight,
      maxVal,
      getX,
      getY,
      downloadPath: createSvgPath(downloadPoints),
      downloadArea: createAreaPath(downloadPoints),
      uploadPath: createSvgPath(uploadPoints),
      uploadArea: createAreaPath(uploadPoints),
      totalPath: createSvgPath(totalPoints),
      yTicks,
      xTicks,
      points: {
        download: downloadPoints,
        upload: uploadPoints,
        total: totalPoints,
      },
    };
  }, [
    boundedData,
    height,
    seriesVisible.download,
    seriesVisible.total,
    seriesVisible.upload,
  ]);

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (boundedData.length === 0 || !chartLayout) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const ratio = Math.max(
      0,
      Math.min(1, (e.clientX - rect.left) / rect.width),
    );
    const index = Math.round(ratio * (boundedData.length - 1));
    setHoverIndex(index);
  };

  const handleMouseLeave = () => {
    setHoverIndex(null);
  };

  if (loading) {
    return (
      <div
        className={cn(
          "flex flex-col rounded-md border border-border bg-surface p-4",
          className,
        )}
      >
        {title && (
          <div className="h-4 w-32 rounded bg-surface-subtle animate-pulse mb-4" />
        )}
        <div
          style={{ height }}
          className="w-full rounded bg-surface-subtle/60 animate-pulse flex items-center justify-center text-xs text-foreground-muted"
        >
          Loading chart data...
        </div>
      </div>
    );
  }

  if (boundedData.length === 0 || !chartLayout) {
    return (
      <div
        className={cn(
          "flex flex-col rounded-md border border-border bg-surface p-4",
          className,
        )}
      >
        {title && (
          <h3 className="text-xs font-semibold text-foreground mb-3">
            {title}
          </h3>
        )}
        <div
          style={{ height }}
          className="flex flex-col items-center justify-center rounded border border-dashed border-border bg-surface-subtle/30 text-xs text-foreground-muted"
        >
          <span>{emptyMessage ?? tStates("waitingTraffic")}</span>
        </div>
      </div>
    );
  }

  const activePoint = hoverIndex !== null ? boundedData[hoverIndex] : null;
  const latestPoint = boundedData[boundedData.length - 1];
  const accessibleSummary = `${title ?? "Traffic chart"}. ${boundedData.length} points. Latest download ${formatBitrate(latestPoint.downloadBps)}, upload ${formatBitrate(latestPoint.uploadBps)}.`;

  return (
    <div
      className={cn(
        "flex min-w-0 flex-col rounded-md border border-border bg-surface p-4 select-none",
        className,
      )}
    >
      {/* Header with Title and Interactive Series Legend */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
        {title && (
          <h3 className="text-xs font-semibold text-foreground tracking-tight">
            {title}
          </h3>
        )}

        {showLegend && (
          <div className="flex items-center gap-3 text-xs">
            {showDownload && (
              <button
                onClick={() =>
                  setVisibleSeries((s) => ({ ...s, download: !s.download }))
                }
                className={cn(
                  "flex items-center gap-1.5 transition-opacity outline-none rounded px-1 py-0.5 cursor-pointer",
                  seriesVisible.download
                    ? "opacity-100"
                    : "opacity-40 line-through text-foreground-muted",
                )}
                aria-pressed={seriesVisible.download}
              >
                <span className="size-2 rounded-full bg-[var(--chart-download)] shrink-0" />
                <span className="font-medium text-foreground-secondary">
                  {t("download")}
                </span>
              </button>
            )}

            {showUpload && (
              <button
                onClick={() =>
                  setVisibleSeries((s) => ({ ...s, upload: !s.upload }))
                }
                className={cn(
                  "flex items-center gap-1.5 transition-opacity outline-none rounded px-1 py-0.5 cursor-pointer",
                  seriesVisible.upload
                    ? "opacity-100"
                    : "opacity-40 line-through text-foreground-muted",
                )}
                aria-pressed={seriesVisible.upload}
              >
                <span className="size-2 rounded-full bg-[var(--chart-upload)] shrink-0" />
                <span className="font-medium text-foreground-secondary">
                  {t("upload")}
                </span>
              </button>
            )}

            {showTotal && (
              <button
                onClick={() =>
                  setVisibleSeries((s) => ({ ...s, total: !s.total }))
                }
                className={cn(
                  "flex items-center gap-1.5 transition-opacity outline-none rounded px-1 py-0.5 cursor-pointer",
                  seriesVisible.total
                    ? "opacity-100"
                    : "opacity-40 line-through text-foreground-muted",
                )}
                aria-pressed={seriesVisible.total}
              >
                <span className="size-2 rounded-full bg-[var(--chart-total)] shrink-0" />
                <span className="font-medium text-foreground-secondary">
                  {t("total")}
                </span>
              </button>
            )}
          </div>
        )}
      </div>

      {/* SVG Interactive Chart Canvas */}
      <div
        className="relative w-full min-w-0 overflow-hidden pl-16 pr-2"
        style={{ height }}
      >
        <div className="absolute inset-y-0 left-0 w-14">
          {chartLayout.yTicks.map((tick, index) => (
            <span
              key={index}
              className="absolute right-2 -translate-y-1/2 whitespace-nowrap font-mono text-[10px] font-medium tabular-nums text-foreground-muted"
              style={{ top: tick.y }}
            >
              {tick.label}
            </span>
          ))}
        </div>

        <div className="relative h-full w-full min-w-0">
          <div className="relative h-[calc(100%-1.75rem)] w-full min-w-0">
            <svg
              width="100%"
              height="100%"
              viewBox={`0 0 ${chartLayout.plotWidth} ${chartLayout.chartHeight + chartLayout.padding.top}`}
              preserveAspectRatio="none"
              onMouseMove={handleMouseMove}
              onMouseLeave={handleMouseLeave}
              className="block h-full w-full cursor-crosshair"
              role="img"
              aria-label={accessibleSummary}
            >
              <defs>
                <linearGradient
                  id={`${gradientId}-download`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="0%"
                    stopColor="var(--chart-download)"
                    stopOpacity="0.18"
                  />
                  <stop
                    offset="100%"
                    stopColor="var(--chart-download)"
                    stopOpacity="0.0"
                  />
                </linearGradient>
                <linearGradient
                  id={`${gradientId}-upload`}
                  x1="0"
                  y1="0"
                  x2="0"
                  y2="1"
                >
                  <stop
                    offset="0%"
                    stopColor="var(--chart-upload)"
                    stopOpacity="0.18"
                  />
                  <stop
                    offset="100%"
                    stopColor="var(--chart-upload)"
                    stopOpacity="0.0"
                  />
                </linearGradient>
              </defs>

              {chartLayout.yTicks.map((tick, i) => (
                <line
                  key={i}
                  x1={0}
                  y1={tick.y}
                  x2={chartLayout.plotWidth}
                  y2={tick.y}
                  stroke="var(--chart-grid)"
                  strokeDasharray="3 3"
                  strokeWidth="1"
                  vectorEffect="non-scaling-stroke"
                />
              ))}

              {seriesVisible.download && (
                <path
                  d={chartLayout.downloadArea}
                  fill={`url(#${gradientId}-download)`}
                />
              )}
              {seriesVisible.upload && (
                <path
                  d={chartLayout.uploadArea}
                  fill={`url(#${gradientId}-upload)`}
                />
              )}
              {seriesVisible.download && (
                <path
                  d={chartLayout.downloadPath}
                  fill="none"
                  stroke="var(--chart-download)"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              )}
              {seriesVisible.upload && (
                <path
                  d={chartLayout.uploadPath}
                  fill="none"
                  stroke="var(--chart-upload)"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              )}
              {seriesVisible.total && (
                <path
                  d={chartLayout.totalPath}
                  fill="none"
                  stroke="var(--chart-total)"
                  strokeWidth="1.5"
                  strokeDasharray="4 2"
                  strokeLinecap="round"
                  vectorEffect="non-scaling-stroke"
                />
              )}

              {hoverIndex !== null && chartLayout && (
                <g>
                  <line
                    x1={chartLayout.getX(hoverIndex)}
                    y1={chartLayout.padding.top}
                    x2={chartLayout.getX(hoverIndex)}
                    y2={chartLayout.padding.top + chartLayout.chartHeight}
                    stroke="var(--foreground-muted)"
                    strokeWidth="1"
                    strokeDasharray="2 2"
                    vectorEffect="non-scaling-stroke"
                  />
                </g>
              )}
            </svg>

            {hoverIndex !== null && seriesVisible.download && (
              <span
                className="pointer-events-none absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-surface bg-[var(--chart-download)]"
                style={{
                  left: `${(chartLayout.points.download[hoverIndex][0] / chartLayout.plotWidth) * 100}%`,
                  top: `${(chartLayout.points.download[hoverIndex][1] / (chartLayout.chartHeight + chartLayout.padding.top)) * 100}%`,
                }}
              />
            )}
            {hoverIndex !== null && seriesVisible.upload && (
              <span
                className="pointer-events-none absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-surface bg-[var(--chart-upload)]"
                style={{
                  left: `${(chartLayout.points.upload[hoverIndex][0] / chartLayout.plotWidth) * 100}%`,
                  top: `${(chartLayout.points.upload[hoverIndex][1] / (chartLayout.chartHeight + chartLayout.padding.top)) * 100}%`,
                }}
              />
            )}
          </div>

          {chartLayout.xTicks.map((tick, index) => (
            <span
              key={index}
              className="absolute bottom-0 -translate-x-1/2 whitespace-nowrap font-mono text-[10px] tabular-nums text-foreground-muted"
              style={{ left: `${(tick.x / chartLayout.plotWidth) * 100}%` }}
            >
              {tick.label}
            </span>
          ))}
        </div>

        {/* Floating Tooltip Box */}
        {activePoint && hoverIndex !== null && chartLayout && (
          <div
            className="pointer-events-none absolute z-30 flex flex-col gap-1 rounded-md border border-border bg-surface/95 p-2 shadow-md backdrop-blur-xs text-xs animate-in fade-in-50 duration-75"
            style={{
              top: 8,
              left: `clamp(64px, calc(64px + ${(chartLayout.getX(hoverIndex) / chartLayout.plotWidth) * 100}% - 75px), calc(100% - 165px))`,
            }}
          >
            <div className="font-mono text-[10px] text-foreground-muted border-b border-border pb-1">
              {formatTimestamp(activePoint.timestamp, "tooltip")}
            </div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] pt-0.5">
              <span className="flex items-center gap-1 text-[var(--chart-download)]">
                <span className="size-1.5 rounded-full bg-[var(--chart-download)]" />
                <span>{t("download")}:</span>
              </span>
              <span className="text-right font-medium tabular-nums font-mono">
                {formatBitrate(activePoint.downloadBps)}
              </span>

              <span className="flex items-center gap-1 text-[var(--chart-upload)]">
                <span className="size-1.5 rounded-full bg-[var(--chart-upload)]" />
                <span>{t("upload")}:</span>
              </span>
              <span className="text-right font-medium tabular-nums font-mono">
                {formatBitrate(activePoint.uploadBps)}
              </span>

              {showTotal && (
                <>
                  <span className="flex items-center gap-1 text-[var(--chart-total)]">
                    <span className="size-1.5 rounded-full bg-[var(--chart-total)]" />
                    <span>Total:</span>
                  </span>
                  <span className="text-right font-medium tabular-nums font-mono">
                    {formatBitrate(
                      activePoint.totalBps ??
                        activePoint.downloadBps + activePoint.uploadBps,
                    )}
                  </span>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
