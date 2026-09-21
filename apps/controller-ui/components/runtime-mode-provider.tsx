"use client";

import React, { createContext, useContext } from "react";

interface RuntimeModeContextValue {
  isDemo: boolean;
}

const RuntimeModeContext = createContext<RuntimeModeContextValue>({
  isDemo: false,
});

export function RuntimeModeProvider({
  isDemo,
  children,
}: {
  isDemo: boolean;
  children: React.ReactNode;
}) {
  return (
    <RuntimeModeContext.Provider value={{ isDemo }}>
      {children}
    </RuntimeModeContext.Provider>
  );
}

export function useRuntimeMode() {
  return useContext(RuntimeModeContext);
}
