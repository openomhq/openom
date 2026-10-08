export const PREVIEW_MODE_LABELS = Object.freeze({
  full: 'full-preview',
  web: 'preview',
});

export function desiredPreviewMode(pullRequest) {
  if (pullRequest?.state !== 'open') return 'none';
  const labels = new Set(
    Array.isArray(pullRequest.labels)
      ? pullRequest.labels.map((label) => label?.name).filter(Boolean)
      : [],
  );
  if (labels.has(PREVIEW_MODE_LABELS.full)) return 'full';
  if (labels.has(PREVIEW_MODE_LABELS.web)) return 'web';
  return 'none';
}
