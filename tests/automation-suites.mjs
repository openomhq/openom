import path from 'node:path';

export const automationSuites = Object.freeze([
  Object.freeze({
    name: 'repository',
    roots: Object.freeze(['tests/repository/']),
  }),
  Object.freeze({
    name: 'deployment',
    roots: Object.freeze(['infra/deployment/']),
  }),
  Object.freeze({
    name: 'preview',
    roots: Object.freeze([
      'infra/preview/',
      'infra/terraform/preview/tests/',
    ]),
  }),
  Object.freeze({
    name: 'terraform',
    roots: Object.freeze(['infra/terraform/tests/']),
  }),
]);

function normalize(file) {
  return file.split(path.sep).join('/').replace(/^\.\//u, '');
}

export function classifyAutomationTests(files, suites = automationSuites) {
  const assigned = new Map(suites.map(({ name }) => [name, []]));
  const unassigned = [];
  const duplicated = [];

  for (const rawFile of files) {
    const file = normalize(rawFile);
    const owners = suites.filter(({ roots }) => roots.some((root) => file.startsWith(root)));
    if (owners.length === 0) {
      unassigned.push(file);
      continue;
    }
    if (owners.length > 1) {
      duplicated.push({ file, suites: owners.map(({ name }) => name) });
      continue;
    }
    assigned.get(owners[0].name).push(file);
  }

  for (const tests of assigned.values()) tests.sort();
  return { assigned, duplicated, unassigned };
}
