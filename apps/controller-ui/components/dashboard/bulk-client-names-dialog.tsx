"use client";

import { useId, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  normalizeClientMac,
  parseClientNameUpdates,
  type ClientNameUpdate,
} from "@/lib/bulk-client-names";
import type { ApiEnvelope, ClientSummary } from "@/lib/network-types";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onUpdated: (updates: Array<{ id: number; name: string }>) => void;
  onSuccess: (count: number) => void;
}

async function findClients(entries: ClientNameUpdate[]) {
  const wanted = new Set(entries.map((entry) => normalizeClientMac(entry.mac)));
  const matches = new Map<string, ClientSummary>();
  for (let offset = 0; offset <= 1_000_000; offset += 200) {
    const response = await fetch(`/api/clients?limit=200&offset=${offset}`, {
      cache: "no-store",
    });
    const result = (await response.json()) as ApiEnvelope<ClientSummary[]>;
    if (!response.ok)
      throw new Error(result.error?.message ?? String(response.status));
    for (const client of result.data) {
      const mac = normalizeClientMac(client.mac);
      if (wanted.has(mac)) matches.set(mac, client);
    }
    if (matches.size === wanted.size) break;
    const total = result.pagination?.total;
    if (total !== undefined ? offset + 200 >= total : result.data.length < 200)
      break;
  }
  return matches;
}

export function BulkClientNamesDialog({
  open,
  onOpenChange,
  onUpdated,
  onSuccess,
}: Props) {
  const t = useTranslations("clients.bulkNames");
  const inputId = useId();
  const [input, setInput] = useState("");
  const [errors, setErrors] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [progress, setProgress] = useState({ completed: 0, total: 0 });
  const pending = useRef(false);

  const changeOpen = (next: boolean) => {
    if (pending.current) return;
    onOpenChange(next);
    if (!next) {
      setInput("");
      setErrors([]);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (pending.current) return;
    const { entries, issues } = parseClientNameUpdates(input);
    if (issues.length || !entries.length) {
      setErrors(
        issues.length
          ? issues.map((issue) => t(issue.reason, { line: issue.line }))
          : [t("empty")],
      );
      return;
    }
    pending.current = true;
    setSaving(true);
    setErrors([]);
    setProgress({ completed: 0, total: 0 });
    try {
      const matches = await findClients(entries);
      const missing = entries.filter(
        (entry) => !matches.has(normalizeClientMac(entry.mac)),
      );
      if (missing.length) {
        setErrors(
          missing.map((entry) =>
            t("notFound", { line: entry.line, mac: entry.mac }),
          ),
        );
        return;
      }
      setProgress({ completed: 0, total: entries.length });
      const updates: Array<{ id: number; name: string }> = [];
      const failures: ClientNameUpdate[] = [];
      const messages: string[] = [];
      for (const entry of entries) {
        const client = matches.get(normalizeClientMac(entry.mac))!;
        try {
          const response = await fetch(`/api/clients/${client.id}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: entry.name }),
          });
          if (!response.ok) {
            const result = await response.json().catch(() => null);
            throw new Error(result?.error?.message ?? String(response.status));
          }
          updates.push({ id: client.id, name: entry.name });
        } catch (error) {
          failures.push(entry);
          messages.push(
            t("updateError", {
              mac: entry.mac,
              message: error instanceof Error ? error.message : String(error),
            }),
          );
        }
        setProgress((current) => ({
          ...current,
          completed: current.completed + 1,
        }));
      }
      if (updates.length) onUpdated(updates);
      if (failures.length) {
        setInput(
          failures.map((entry) => `${entry.mac} ${entry.name}`).join("\n"),
        );
        setErrors([
          t("partial", { updated: updates.length, failed: failures.length }),
          ...messages,
        ]);
      } else {
        setInput("");
        onOpenChange(false);
        onSuccess(updates.length);
      }
    } catch (error) {
      setErrors([
        t("loadError", {
          message: error instanceof Error ? error.message : String(error),
        }),
      ]);
    } finally {
      pending.current = false;
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={changeOpen}>
      <DialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-2xl"
        showCloseButton={!saving}
      >
        <form
          onSubmit={submit}
          className="flex min-w-0 flex-col gap-4"
          aria-busy={saving}
        >
          <DialogHeader>
            <DialogTitle>{t("title")}</DialogTitle>
            <DialogDescription>{t("description")}</DialogDescription>
          </DialogHeader>
          <div className="flex min-w-0 flex-col gap-2">
            <Label htmlFor={inputId}>{t("inputLabel")}</Label>
            <textarea
              id={inputId}
              value={input}
              onChange={(event) => {
                setInput(event.target.value);
                setErrors([]);
              }}
              placeholder={t("placeholder")}
              rows={12}
              disabled={saving}
              spellCheck={false}
              autoCapitalize="off"
              aria-invalid={errors.length > 0 || undefined}
              aria-describedby={`${inputId}-hint${errors.length ? ` ${inputId}-errors` : ""}`}
              className="min-h-64 w-full resize-y rounded-md border border-border bg-surface px-3 py-2 font-mono text-sm text-foreground outline-none placeholder:text-foreground-muted focus-visible:border-accent focus-visible:ring-1 focus-visible:ring-accent disabled:opacity-50"
            />
            <p id={`${inputId}-hint`} className="text-xs text-foreground-muted">
              {t("hint")}
            </p>
          </div>
          {errors.length > 0 && (
            <div
              id={`${inputId}-errors`}
              role="alert"
              className="max-h-36 overflow-y-auto rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive"
            >
              {errors.map((error, index) => (
                <p key={index}>{error}</p>
              ))}
            </div>
          )}
          {saving && (
            <p role="status" className="text-xs text-foreground-muted">
              {progress.total ? t("progress", progress) : t("matching")}
            </p>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={saving}
              onClick={() => changeOpen(false)}
            >
              {t("cancel")}
            </Button>
            <Button type="submit" disabled={saving || !input.trim()}>
              {saving && (
                <Loader2 data-icon="inline-start" className="animate-spin" />
              )}
              {saving ? t("saving") : t("confirm")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
