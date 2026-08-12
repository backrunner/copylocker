import { createConfiguredSearchResponse } from 'svedocs/search';
import config from 'virtual:svedocs/config';
import records from 'virtual:svedocs/search';
import type { RequestHandler } from './$types';

export const prerender = false;

export const GET: RequestHandler = ({ request }) => {
  // Local MiniSearch provider — no platform bindings required.
  return createConfiguredSearchResponse(config, records, request);
};
