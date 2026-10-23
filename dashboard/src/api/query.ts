import { createContext, useContext } from 'react';
import { keepPreviousData, QueryClient, useQuery } from '@tanstack/react-query';
import { getJson } from './client';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 2_000,
      refetchOnWindowFocus: false,
      // Keep showing the last good payload while a refresh fails or a new
      // query key loads; pages surface the error separately.
      placeholderData: keepPreviousData,
    },
  },
});

interface PollingState {
  paused: boolean;
  setPaused: (paused: boolean) => void;
}

export const PollingContext = createContext<PollingState>({ paused: false, setPaused: () => undefined });

export const usePolling = () => useContext(PollingContext);

/** GET a backend path with polling that honours the global pause switch. */
export function useApi<T>(path: string | null, interval = 5_000) {
  const { paused } = usePolling();
  return useQuery({
    queryKey: [path],
    queryFn: () => getJson<T>(path as string),
    enabled: path !== null,
    refetchInterval: paused || interval <= 0 ? false : interval,
  });
}
