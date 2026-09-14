"use client";

import React, { useState } from "react";
import { Sidebar } from "@/components/app-shell/sidebar";
import { Header } from "@/components/app-shell/header";
import { PageContainer } from "@/components/app-shell/page-container";

interface AppLayoutProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
  gatewayName?: string;
  gatewayStatus?: "online" | "offline" | "degraded";
  isLive?: boolean;
  username?: string;
  toolbar?: React.ReactNode;
  warningBanner?: string | React.ReactNode;
  headerActions?: React.ReactNode;
}

export function AppLayout({
  children,
  title = "Overview",
  subtitle,
  gatewayName = "OpenWrt Gateway",
  gatewayStatus = "online",
  isLive = true,
  username = "admin",
  toolbar,
  warningBanner,
  headerActions,
}: AppLayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="flex min-h-screen w-full bg-background text-foreground">
      {/* Sidebar (Desktop sticky & Mobile drawer) */}
      <Sidebar
        mobileOpen={mobileMenuOpen}
        onMobileClose={() => setMobileMenuOpen(false)}
        gatewayStatus={gatewayStatus}
      />

      {/* Main Content Column */}
      <div className="flex flex-1 flex-col min-w-0 overflow-x-hidden">
        <Header
          title={title}
          subtitle={subtitle}
          gatewayName={gatewayName}
          gatewayStatus={gatewayStatus}
          isLive={isLive}
          username={username}
          onMobileMenuToggle={() => setMobileMenuOpen(true)}
          actions={headerActions}
        />

        <PageContainer toolbar={toolbar} warningBanner={warningBanner}>
          {children}
        </PageContainer>
      </div>
    </div>
  );
}
