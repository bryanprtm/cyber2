import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getRandomInt(min: number, max: number): number {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function formatDate(date: Date): string {
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

export function applyGlitchEffect(element: HTMLElement | null): void {
  if (!element) return;
  
  const originalTransform = element.style.transform;
  
  element.style.transform = `translateX(${Math.random() * 3 - 1.5}px) translateY(${Math.random() * 3 - 1.5}px)`;
  
  setTimeout(() => {
    element.style.transform = originalTransform;
  }, 150);
}
