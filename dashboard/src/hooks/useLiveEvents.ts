import { useEffect, useState } from 'react';
import type { EventRow } from '../types/api';

export function useLiveEvents(limit = 50) {
  const [events, setEvents] = useState<EventRow[]>([]);

  useEffect(() => {
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${window.location.host}/ws/events`);
    socket.onmessage = (message) => {
      const parsed = JSON.parse(message.data);
      if (parsed.type === 'event' && parsed.event) {
        setEvents((current) => [parsed.event, ...current].slice(0, limit));
      }
    };
    return () => socket.close();
  }, [limit]);

  return events;
}
