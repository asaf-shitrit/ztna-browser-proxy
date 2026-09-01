export interface SessionApp {
  id: string;
  hosts: string[];
  ports: number[];
}

export interface PopSession {
  proxyUser: string;
  proxySecret: string;
  expiresAt: number;
  identity: {
    sub: string;
    email?: string;
    name?: string;
    groups: string[];
  };
  apps: SessionApp[];
  proxy: { host: string; port: number };
}

export interface ExtensionState {
  status: 'disconnected' | 'connecting' | 'connected' | 'error';
  identity?: PopSession['identity'];
  apps: SessionApp[];
  error?: string;
  expiresAt?: number;
}

export type Message =
  | { type: 'GET_STATE' }
  | { type: 'SIGN_IN' }
  | { type: 'SIGN_OUT' };
