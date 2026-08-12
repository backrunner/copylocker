import { error } from '@sveltejs/kit';
import { createConfiguredOgImageFormat, createConfiguredOgImageRenderer, createConfiguredOgImageTemplate, createPageOgImagePath, createPageOgImageResponse, isOgImageEnabled } from 'svedocs/og';
import config from 'virtual:svedocs/server-config';
import pages from 'virtual:svedocs/pages';
import type { RequestHandler } from './$types';

// OG images are pre-generated into static/og by the svedocs vite plugin during
// the build; this endpoint is the runtime fallback, so it is not prerendered.
export const prerender = false;

const format = createConfiguredOgImageFormat(config);
const template = createConfiguredOgImageTemplate(config);

export const GET: RequestHandler = async ({ params }) => {
  if (!isOgImageEnabled(config)) error(404, 'OG images are disabled.');
  const requestPath = `/og/${params.path}`;
  const page = pages.find((candidate) => createPageOgImagePath(candidate, format) === requestPath);
  if (!page) error(404, `No OG image found for ${requestPath}`);
  return createPageOgImageResponse(config, page, {
    format,
    renderer: createConfiguredOgImageRenderer(config),
    ...(template ? { template } : {})
  });
};
