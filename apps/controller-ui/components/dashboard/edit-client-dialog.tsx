"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { ClientSummary } from "@/lib/network-types";

const DEVICE_TYPES = [
  "smartphone",
  "tablet",
  "laptop",
  "desktop",
  "tv",
  "nas",
  "server",
  "printer",
  "camera",
  "game-console",
  "speaker",
  "router",
  "iot",
] as const;

interface EditClientDialogProps {
  client: ClientSummary | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess: (updated: ClientSummary) => void;
  showToast?: (toast: {
    title: string;
    description?: string;
    status: "success" | "error";
  }) => void;
}

interface EditClientFormProps {
  client: ClientSummary;
  onClose: () => void;
  onSuccess: (updated: ClientSummary) => void;
  showToast?: EditClientDialogProps["showToast"];
}

function EditClientForm({
  client,
  onClose,
  onSuccess,
  showToast,
}: EditClientFormProps) {
  const t = useTranslations("clients");
  const initialExplicitType = client.identity?.device_type_override;
  const [name, setName] = useState(client.name || "");
  const [deviceType, setDeviceType] = useState(
    initialExplicitType
      ? initialExplicitType.toLowerCase().replaceAll("_", "-")
      : "auto",
  );
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    setSaving(true);
    try {
      const payload: {
        name: string | null;
        device_type: string | null;
      } = {
        name: name.trim().length > 0 ? name.trim() : null,
        device_type: deviceType === "auto" ? null : deviceType,
      };

      const response = await fetch(`/api/clients/${client.id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorJson = await response.json().catch(() => null);
        throw new Error(
          errorJson?.error?.message ??
            `Failed to update client (${response.status})`,
        );
      }

      const result = await response.json();
      const updatedClient = (result.data?.client ??
        result.data) as ClientSummary;

      showToast?.({
        title: t("editClientDialog.saveSuccess"),
        status: "success",
      });
      onSuccess(updatedClient);
      onClose();
    } catch (err) {
      showToast?.({
        title: t("editClientDialog.saveError"),
        description: err instanceof Error ? err.message : String(err),
        status: "error",
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <DialogHeader>
        <DialogTitle>{t("editClientDialog.title")}</DialogTitle>
        <DialogDescription>
          {t("editClientDialog.description")}
        </DialogDescription>
      </DialogHeader>

      <div className="flex flex-col gap-4 py-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="client-name">{t("editClientDialog.nameLabel")}</Label>
          <Input
            id="client-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("editClientDialog.namePlaceholder")}
            disabled={saving}
            autoFocus
          />
        </div>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="client-device-type">
            {t("editClientDialog.deviceTypeLabel")}
          </Label>
          <Select
            value={deviceType}
            onValueChange={setDeviceType}
            disabled={saving}
            className="w-full"
          >
            <SelectTrigger id="client-device-type" className="h-8 w-full">
              <SelectValue>
                {deviceType === "auto"
                  ? t("editClientDialog.deviceTypeAuto")
                  : t(`editClientDialog.deviceTypes.${deviceType}`)}
              </SelectValue>
            </SelectTrigger>
            <SelectContent align="start">
              <SelectItem value="auto">
                {t("editClientDialog.deviceTypeAuto")}
              </SelectItem>
              {DEVICE_TYPES.map((type) => (
                <SelectItem key={type} value={type}>
                  {t(`editClientDialog.deviceTypes.${type}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <DialogFooter>
        <Button
          type="button"
          variant="outline"
          onClick={onClose}
          disabled={saving}
        >
          {t("editClientDialog.cancel")}
        </Button>
        <Button type="submit" disabled={saving}>
          {saving ? t("editClientDialog.saving") : t("editClientDialog.save")}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function EditClientDialog({
  client,
  open,
  onOpenChange,
  onSuccess,
  showToast,
}: EditClientDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        {client && open && (
          <EditClientForm
            key={client.id}
            client={client}
            onClose={() => onOpenChange(false)}
            onSuccess={onSuccess}
            showToast={showToast}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
