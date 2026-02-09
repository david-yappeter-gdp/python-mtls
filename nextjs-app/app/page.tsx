import { getProxyClient } from '@/lib/proxyClient';
import styles from './page.module.css';

// Disable caching - fetch fresh data on every request
export const dynamic = 'force-dynamic';
export const revalidate = 0;

interface EndpointData {
  name: string;
  endpoint: string;
  data: any;
  error?: string;
}

async function fetchAllEndpoints(): Promise<EndpointData[]> {
  const client = getProxyClient();
  const endpoints: EndpointData[] = [];

  // Fetch server info
  try {
    const data = await client.getServerInfo();
    endpoints.push({
      name: 'Server Info',
      endpoint: '/',
      data,
    });
  } catch (error) {
    endpoints.push({
      name: 'Server Info',
      endpoint: '/',
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Fetch health
  try {
    const data = await client.getHealth();
    endpoints.push({
      name: 'Health Check',
      endpoint: '/health',
      data,
    });
  } catch (error) {
    endpoints.push({
      name: 'Health Check',
      endpoint: '/health',
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Fetch secure data
  try {
    const data = await client.getSecure();
    endpoints.push({
      name: 'Secure Data',
      endpoint: '/secure',
      data,
    });
  } catch (error) {
    endpoints.push({
      name: 'Secure Data',
      endpoint: '/secure',
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  // Test no-cert endpoint
  try {
    const data = await client.testNoCert();
    endpoints.push({
      name: 'No Certificate Test',
      endpoint: '/no-cert',
      data,
    });
  } catch (error) {
    endpoints.push({
      name: 'No Certificate Test',
      endpoint: '/no-cert',
      data: null,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }

  return endpoints;
}

export default async function Home() {
  const endpoints = await fetchAllEndpoints();

  return (
    <main className={styles.main}>
      <div className={styles.container}>
        <header className={styles.header}>
          <h1>🔒 mTLS Proxy Client</h1>
          <p>Next.js application connecting to HTTPS proxy server</p>
        </header>

        <div className={styles.info}>
          <p>
            <strong>Proxy Server:</strong> {process.env.PROXY_SERVER_URL || 'https://localhost:8080'}
          </p>
          <p>
            <strong>Certificate Verification:</strong>{' '}
            {process.env.SKIP_CERT_VERIFICATION === 'true' ? '❌ Disabled (Dev Mode)' : '✅ Enabled'}
          </p>
        </div>

        <div className={styles.endpoints}>
          {endpoints.map((endpoint, index) => (
            <div key={index} className={styles.card}>
              <div className={styles.cardHeader}>
                <h2>{endpoint.name}</h2>
                <code className={styles.endpoint}>{endpoint.endpoint}</code>
              </div>
              
              {endpoint.error ? (
                <div className={styles.error}>
                  <p>❌ Error: {endpoint.error}</p>
                </div>
              ) : (
                <div className={styles.response}>
                  <pre>{JSON.stringify(endpoint.data, null, 2)}</pre>
                </div>
              )}
            </div>
          ))}
        </div>

        <footer className={styles.footer}>
          <p>Server-side rendered with Next.js App Router</p>
        </footer>
      </div>
    </main>
  );
}
