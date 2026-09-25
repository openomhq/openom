import cf from 'cloudfront';

const routes = cf.kvs();
const APP_SUFFIX = '.app.dev.openom.org';
const API_SUFFIX = '.api.dev.openom.org';
const PAGES_SUFFIX = '.pages.dev';
const LAMBDA_URL_SUFFIX = '.lambda-url.eu-central-1.on.aws';

function notFound() {
  return {
    statusCode: 404,
    statusDescription: 'Not Found',
    headers: {
      'cache-control': { value: 'no-store' },
      'content-type': { value: 'application/problem+json' },
    },
    body: JSON.stringify({ code: 'preview_not_found' }),
  };
}

function slugForHost(host, suffix) {
  if (typeof host !== 'string' || !host.endsWith(suffix)) return null;
  const slug = host.slice(0, -suffix.length);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,43}[a-z0-9])?$/.test(slug)) return null;
  return slug;
}

function trustedOrigin(value, suffix) {
  return typeof value === 'string'
    && value.endsWith(suffix)
    && /^[a-z0-9.-]+$/.test(value)
    && !value.startsWith('.')
    && value.length > suffix.length;
}

function parseRoute(value, slug) {
  let route;
  try {
    route = JSON.parse(value);
  } catch (error) {
    return null;
  }
  if (!route || route.version !== 1 || route.slug !== slug) return null;
  if (route.mode !== 'web' && route.mode !== 'full') return null;
  if (!trustedOrigin(route.webOrigin, PAGES_SUFFIX)) return null;
  if (route.mode === 'full' && !trustedOrigin(route.apiOrigin, LAMBDA_URL_SUFFIX)) return null;
  return route;
}

async function loadRoute(slug) {
  try {
    const value = await routes.get(slug);
    return value ? parseRoute(value, slug) : null;
  } catch (error) {
    return null;
  }
}

async function handler(event) {
  const request = event.request;
  const host = request.headers.host && request.headers.host.value;
  const appSlug = slugForHost(host, APP_SUFFIX);
  const apiSlug = appSlug ? null : slugForHost(host, API_SUFFIX);
  const slug = appSlug || apiSlug;
  if (!slug) return notFound();

  const route = await loadRoute(slug);
  if (!route) return notFound();

  if (appSlug) {
    cf.updateRequestOrigin({
      domainName: route.webOrigin,
      originAccessControlConfig: { enabled: false },
    });
    return request;
  }

  if (route.mode !== 'full') return notFound();
  cf.updateRequestOrigin({ domainName: route.apiOrigin });
  return request;
}
