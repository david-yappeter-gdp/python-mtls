import https from 'https';
import fs from 'fs';
import path from 'path';

interface ProxyClientConfig {
  baseUrl: string;
  caCertPath?: string;
  skipVerification?: boolean;
}

class ProxyClient {
  private baseUrl: string;
  private httpsAgent: https.Agent;

  constructor(config: ProxyClientConfig) {
    this.baseUrl = config.baseUrl;

    // Configure HTTPS agent
    const agentOptions: https.AgentOptions = {};

    if (config.skipVerification) {
      // For development: skip certificate verification
      agentOptions.rejectUnauthorized = false;
    } else if (config.caCertPath) {
      // For production: verify with CA certificate
      try {
        const caCertPath = path.resolve(process.cwd(), config.caCertPath);
        const ca = fs.readFileSync(caCertPath);
        agentOptions.ca = ca;
        agentOptions.rejectUnauthorized = true;
      } catch (error) {
        console.error('Failed to load CA certificate:', error);
        throw new Error('CA certificate not found. Please ensure certificates are generated.');
      }
    }

    this.httpsAgent = new https.Agent(agentOptions);
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    try {
      const response = await fetch(url, {
        ...options,
        // @ts-ignore - Node.js fetch supports agent
        agent: this.httpsAgent,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error(`Request to ${endpoint} failed:`, error);
      throw error;
    }
  }

  async getServerInfo() {
    return this.request('/');
  }

  async getHealth() {
    return this.request('/health');
  }

  async getSecure() {
    return this.request('/secure');
  }

  async testNoCert() {
    return this.request('/no-cert');
  }

  async echo(data: any) {
    return this.request('/echo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
  }
}

// Singleton instance
let proxyClient: ProxyClient | null = null;

export function getProxyClient(): ProxyClient {
  if (!proxyClient) {
    const config: ProxyClientConfig = {
      baseUrl: process.env.PROXY_SERVER_URL || 'https://localhost:8080',
      skipVerification: process.env.SKIP_CERT_VERIFICATION === 'true',
      caCertPath: process.env.PROXY_CA_CERT_PATH,
    };

    proxyClient = new ProxyClient(config);
  }

  return proxyClient;
}

export default ProxyClient;
