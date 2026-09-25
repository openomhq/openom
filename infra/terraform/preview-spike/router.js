import cf from 'cloudfront';

const routes = cf.kvs();

function notFound() {
  return {
    statusCode: 404,
    statusDescription: 'Not Found',
    headers: { 'cache-control': { value: 'no-store' } },
  };
}

async function handler(event) {
  const request = event.request;
  const parts = request.uri.split('/');
  const route = parts[1];
  if (!route) return notFound();

  request.uri = `/${parts.slice(2).join('/')}`;

  let domainName;
  try {
    domainName = await routes.get(route);
  } catch (error) {
    return notFound();
  }
  if (!domainName) return notFound();

  if (route === 'web') {
    cf.updateRequestOrigin({
      domainName,
      originAccessControlConfig: {
        enabled: false,
      },
    });
    return request;
  }

  cf.updateRequestOrigin({ domainName });
  return request;
}
