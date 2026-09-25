export async function handler() {
  return {
    statusCode: 404,
    headers: {
      'cache-control': 'no-store',
      'content-type': 'application/problem+json',
    },
    body: JSON.stringify({ code: 'preview_not_found' }),
  };
}
