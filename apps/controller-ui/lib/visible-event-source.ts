/** Reconnect on return so the stream's initial snapshot catches up immediately. */
export function subscribeVisibleEventSource(
  url: string,
  configure: (events: EventSource) => void,
) {
  let events: EventSource | null = null;
  const sync = () => {
    if (document.hidden) {
      events?.close();
      events = null;
    } else if (!events) {
      events = new EventSource(url);
      configure(events);
    }
  };
  document.addEventListener("visibilitychange", sync);
  sync();
  return () => {
    document.removeEventListener("visibilitychange", sync);
    events?.close();
  };
}
