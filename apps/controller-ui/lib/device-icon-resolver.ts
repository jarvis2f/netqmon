export type DeviceIconType =
  | "smartphone"
  | "tablet"
  | "laptop"
  | "desktop"
  | "tv"
  | "nas"
  | "server"
  | "printer"
  | "camera"
  | "game-console"
  | "speaker"
  | "router"
  | "iot"
  | "unknown";

interface DeviceLike {
  name?: string | null;
  vendor?: string | null;
  mac?: string | null;
  identity?: {
    device_type?: string | null;
    model?: string | null;
    os_family?: string | null;
    vendor?: string | null;
  } | null;
}

export function resolveDeviceIconType(client: DeviceLike): DeviceIconType {
  const explicit = normalizeDeviceType(client.identity?.device_type);
  if (explicit) return explicit;

  const text = [client.name, client.identity?.model, client.identity?.os_family]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/\b(iphone|android phone|galaxy|pixel)\b/.test(text)) return "smartphone";
  if (/\b(ipad|tablet)\b/.test(text)) return "tablet";
  if (/\b(macbook|laptop|notebook)\b/.test(text)) return "laptop";
  if (/\b(desktop|imac|workstation)\b/.test(text)) return "desktop";
  if (
    /\b(apple tv|apple-tv|chromecast|android tv|android-tv|television|smart tv)\b/.test(
      text,
    )
  )
    return "tv";
  if (/\b(synology|qnap|diskstation|nas)\b/.test(text)) return "nas";
  if (/\b(playstation|xbox|nintendo|switch)\b/.test(text))
    return "game-console";
  if (/\b(printer|epson|brother)\b/.test(text)) return "printer";
  if (/\b(camera|cam|nvr)\b/.test(text)) return "camera";
  if (/\b(homepod|speaker|sonos)\b/.test(text)) return "speaker";
  if (/\b(router|gateway|openwrt)\b/.test(text)) return "router";
  if (/\b(server)\b/.test(text)) return "server";
  return "unknown";
}

function normalizeDeviceType(value?: string | null): DeviceIconType | null {
  const key = value?.toLowerCase().replaceAll("_", "-");
  if (!key) return null;
  if (key === "phone" || key === "smartphone") return "smartphone";
  if (key === "tablet") return "tablet";
  if (key === "laptop") return "laptop";
  if (key === "desktop" || key === "computer") return "desktop";
  if (key === "tv" || key === "television" || key === "media-player")
    return "tv";
  if (key === "nas") return "nas";
  if (key === "server") return "server";
  if (key === "printer") return "printer";
  if (key === "camera" || key === "doorbell") return "camera";
  if (key === "game-console" || key === "console") return "game-console";
  if (key === "speaker") return "speaker";
  if (["router", "access-point", "bridge", "hub"].includes(key))
    return "router";
  if (
    [
      "light",
      "switch",
      "plug",
      "thermostat",
      "appliance",
      "wearable",
      "sensor",
      "iot",
    ].includes(key)
  )
    return "iot";
  return null;
}
