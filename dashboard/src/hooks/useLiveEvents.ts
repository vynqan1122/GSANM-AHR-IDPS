import { createContext, useContext, useEffect, useRef, useState } from 'react';
import type { EventRow } from '../types/api';

export type LiveStatus = 'connecting' | 'live' | 'reconnecting';

export interface LiveEventsState {
  events: EventRow[];
  status: LiveStatus;
  /** event_ids that arrived over the socket in this session, for row highlight. */
  freshIds: Set<string>;
  clear: () => void;
}

export const LiveEventsContext = createContext<LiveEventsState>({
  events: [],
  status: 'connecting',
  freshIds: new Set(),
  clear: () => undefined,
});

export const useLiveEventsContext = () => useContext(LiveEventsContext);

/** One shared WebSocket for the app, reconnecting with capped backoff. */
export function useLiveEvents(limit = 200): LiveEventsState {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [status, setStatus] = useState<LiveStatus>('connecting');
  const freshIds = useRef(new Set<string>());

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry = 0;
    let timer: number | undefined;
    let closed = false;

    const connect = () => {
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
      socket = new WebSocket(`${scheme}://${window.location.host}/ws/events`);
      socket.onopen = () => {
        retry = 0;
        setStatus('live');
      };
      socket.onmessage = (message) => {
        let parsed: { type?: string; event?: EventRow };
        try {
          parsed = JSON.parse(message.data);
        } catch {
          return;
        }
        if (parsed.type === 'event' && parsed.event) {
          const event = parsed.event;
          freshIds.current.add(event.event_id);
          setEvents((current) => [event, ...current].slice(0, limit));
        }
      };
      socket.onclose = () => {
        if (closed) return;
        setStatus('reconnecting');
        const delay = Math.min(15_000, 1_000 * 2 ** retry);
        retry += 1;
        timer = window.setTimeout(connect, delay);
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      socket?.close();
    };
  }, [limit]);

  return {
    events,
    status,
    freshIds: freshIds.current,
    clear: () => {
      freshIds.current.clear();
      setEvents([]);
    },
  };
}
