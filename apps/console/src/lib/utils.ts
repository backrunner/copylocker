import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
	return twMerge(clsx(inputs));
}

export function formatTimestamp(seconds: number | null | undefined): string {
	if (seconds === null || seconds === undefined) return '—';
	return new Date(seconds * 1000).toLocaleString('zh-CN', { hour12: false });
}
