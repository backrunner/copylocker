import {
  CopyLockerCommandError,
  HOST_UNKNOWN_FATAL,
  stableErrorCode,
  type CopyLockerBridge,
  type NativeState,
} from '../shared'

export { CopyLockerCommandError }
export type { CopyLockerBridge, NativeState }

declare global {
  interface Window {
    __cl?: CopyLockerBridge
  }
}

/** Renderer-only client. Every operation crosses the fixed preload bridge. */
export class CopyLockerRendererClient {
  readonly #bridge: CopyLockerBridge

  constructor(bridge: CopyLockerBridge = requireBridge()) {
    this.#bridge = bridge
  }

  async activate(key: string): Promise<void> {
    return this.#call(() => this.#bridge.activate(key))
  }

  async deactivate(): Promise<void> {
    return this.#call(() => this.#bridge.deactivate())
  }

  /** Advisory UI state only. Never use this value as a product gate. */
  async state(): Promise<NativeState> {
    return this.#call(() => this.#bridge.state())
  }

  async unseal(feature: string, data: Uint8Array): Promise<Uint8Array> {
    return this.#call(() => this.#bridge.unseal(feature, data))
  }

  async challenge(input: Uint8Array): Promise<Uint8Array> {
    return this.#call(() => this.#bridge.challenge(input))
  }

  async offlineRequest(key: string): Promise<Uint8Array> {
    return this.#call(() => this.#bridge.offlineRequest(key))
  }

  async offlineImport(data: Uint8Array): Promise<void> {
    return this.#call(() => this.#bridge.offlineImport(data))
  }

  async importOlk(data: string): Promise<void> {
    return this.#call(() => this.#bridge.importOlk(data))
  }

  async #call<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation()
    } catch (error) {
      if (error instanceof CopyLockerCommandError) throw error
      throw new CopyLockerCommandError(stableErrorCode(error))
    }
  }
}

export function createRendererClient(bridge?: CopyLockerBridge): CopyLockerRendererClient {
  return new CopyLockerRendererClient(bridge)
}

function requireBridge(): CopyLockerBridge {
  if (typeof window === 'undefined' || !window.__cl) {
    throw new CopyLockerCommandError(HOST_UNKNOWN_FATAL)
  }
  return window.__cl
}
