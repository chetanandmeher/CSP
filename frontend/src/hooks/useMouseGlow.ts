import { useEffect } from 'react';

/**
 * useMouseGlow — Attaches a global mousemove listener that tracks the cursor
 * position relative to every `.glass-panel` element on the page and moves the
 * corresponding `.mouse-glow` child element to create the hover-glow effect.
 *
 * Re-registers the listener whenever `activeView` changes so that newly
 * mounted panels are also tracked.
 */
export function useMouseGlow(activeView: string): void {
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      const panels = document.querySelectorAll('.glass-panel');
      panels.forEach((panel) => {
        const rect = panel.getBoundingClientRect();
        const glow = panel.querySelector('.mouse-glow') as HTMLElement | null;
        if (glow) {
          glow.style.left = `${e.clientX - rect.left}px`;
          glow.style.top  = `${e.clientY - rect.top}px`;
        }
      });
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, [activeView]);
}
