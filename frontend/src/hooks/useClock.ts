import { useState, useEffect } from 'react';

/**
 * useClock — Returns a live UTC time string, updated every second.
 * Example output: "Mon, 02 Jun 2026 14:19:00 UTC"
 */
export function useClock(): string {
  const [utcTime, setUtcTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };

    updateTime(); // set immediately on mount
    const interval = setInterval(updateTime, 1000);

    return () => clearInterval(interval);
  }, []);

  return utcTime;
}
