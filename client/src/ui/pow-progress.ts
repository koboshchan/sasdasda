// Wires a "Verifying... N%" progress bar (see the .pow-progress markup in
// index.html) to a crypto/pow.ts progress callback, so a difficulty-5 solve
// gives the user feedback instead of looking like a frozen button.
export interface ProgressHandle {
  onProgress: (attempts: number, estimatedTotal: number) => void;
  show: () => void;
  hide: () => void;
}

export function bindPowProgress(containerId: string, labelId: string, fillId: string): ProgressHandle {
  const container = document.getElementById(containerId) as HTMLElement;
  const label = document.getElementById(labelId) as HTMLElement;
  const fill = document.getElementById(fillId) as HTMLElement;

  return {
    onProgress(attempts, estimatedTotal) {
      const pct = Math.min(100, Math.round((attempts / estimatedTotal) * 100));
      label.textContent = `Verifying... ${pct}%`;
      fill.style.width = `${pct}%`;
    },
    show() {
      fill.style.width = '0%';
      label.textContent = 'Verifying...';
      container.style.display = 'block';
    },
    hide() {
      container.style.display = 'none';
    },
  };
}
