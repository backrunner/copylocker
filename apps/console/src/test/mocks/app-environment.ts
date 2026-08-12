// vitest 环境下 $app/environment 的替身（SvelteKit 虚拟模块在 vitest 中不可解析）。
export const browser = true;
export const dev = true;
export const building = false;
export const version = 'test';
