declare namespace App {
  interface Platform {
    env: Record<string, unknown>;
    context: {
      waitUntil(promise: Promise<unknown>): void;
    };
    caches: CacheStorage;
  }
}
