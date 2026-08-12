// vitest 环境下 $app/navigation 的替身（SvelteKit 虚拟模块在 vitest 中不可解析）。
export const goto = async (): Promise<void> => {};
export const invalidate = async (): Promise<void> => {};
export const invalidateAll = async (): Promise<void> => {};
export const beforeNavigate = (): void => {};
export const afterNavigate = (): void => {};
export const onNavigate = (): void => {};
export const pushState = (): void => {};
export const replaceState = (): void => {};
