import { NextRequest, NextResponse } from 'next/server';
import { getProxyClient } from '@/lib/proxyClient';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const client = getProxyClient();
    const result = await client.echo(body);

    return NextResponse.json(result);
  } catch (error) {
    console.error('Echo API error:', error);
    return NextResponse.json(
      { error: 'Failed to echo data', message: error instanceof Error ? error.message : 'Unknown error' },
      { status: 500 }
    );
  }
}
