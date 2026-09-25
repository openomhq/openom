#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const plan = JSON.parse(readFileSync(0, 'utf8'));
const resources = plan.planned_values?.root_module?.resources ?? [];

function resource(address) {
  const value = resources.find((candidate) => candidate.address === address);
  assert.ok(value, `plan is missing ${address}`);
  return value.values;
}

for (const change of plan.resource_changes ?? []) {
  assert.equal(change.change.actions.includes('delete'), false, `${change.address} would be deleted`);
}

const distribution = resource('aws_cloudfront_distribution.preview');
assert.equal(distribution.enabled, true);
assert.equal(distribution.http_version, 'http2');
assert.equal(distribution.wait_for_deployment, true);
assert.deepEqual(distribution.aliases, ['*.api.dev.openom.org', '*.app.dev.openom.org']);
assert.equal(distribution.default_cache_behavior[0].viewer_protocol_policy, 'redirect-to-https');
assert.equal(distribution.default_cache_behavior[0].target_origin_id, 'protected-lambda-sink');
assert.equal(distribution.default_cache_behavior[0].function_association[0].event_type, 'viewer-request');
assert.equal(distribution.origin[0].origin_id, 'protected-lambda-sink');
assert.deepEqual(distribution.origin[0].custom_origin_config[0].origin_ssl_protocols, ['TLSv1.2']);

const originAccess = resource('aws_cloudfront_origin_access_control.preview_api');
assert.equal(originAccess.origin_access_control_origin_type, 'lambda');
assert.equal(originAccess.signing_behavior, 'always');
assert.equal(originAccess.signing_protocol, 'sigv4');

const sinkUrl = resource('aws_lambda_function_url.router_sink');
assert.equal(sinkUrl.authorization_type, 'AWS_IAM');

for (const address of ['cloudflare_dns_record.preview_app', 'cloudflare_dns_record.preview_api']) {
  const record = resource(address);
  assert.equal(record.type, 'CNAME');
  assert.equal(record.proxied, false);
}

const cors = resource('cloudflare_r2_bucket_cors.preview').rules[0];
assert.deepEqual(cors.allowed.origins, ['https://*.app.dev.openom.org']);
assert.deepEqual(cors.allowed.methods, ['GET', 'HEAD', 'PUT']);
assert.deepEqual(cors.allowed.headers, ['content-type', 'x-amz-checksum-sha256']);

const publicAccess = resource('aws_s3_bucket_public_access_block.artifacts');
assert.equal(publicAccess.block_public_acls, true);
assert.equal(publicAccess.block_public_policy, true);
assert.equal(publicAccess.ignore_public_acls, true);
assert.equal(publicAccess.restrict_public_buckets, true);

const artifactLifecycle = resource('aws_s3_bucket_lifecycle_configuration.artifacts').rule[0];
assert.equal(artifactLifecycle.status, 'Enabled');
assert.equal(artifactLifecycle.expiration[0].days, 7);
assert.equal(artifactLifecycle.abort_incomplete_multipart_upload[0].days_after_initiation, 1);

const deployTrust = JSON.parse(resource('aws_iam_role.preview_deploy').assume_role_policy);
const trustCondition = deployTrust.Statement[0].Condition;
assert.equal(trustCondition.StringEquals['token.actions.githubusercontent.com:aud'], 'sts.amazonaws.com');
assert.equal(
  trustCondition.StringLike['token.actions.githubusercontent.com:sub'],
  'repo:openomhq@*/openom@*:environment:preview',
);

const pages = resource('cloudflare_pages_project.preview');
assert.equal(pages.name, 'openom-preview');
assert.equal(pages.source, null);

const objectStore = resource('cloudflare_r2_bucket.preview');
assert.equal(objectStore.name, 'openom-preview');
assert.equal(objectStore.storage_class, 'Standard');

process.stdout.write('[Preview] standing infrastructure plan satisfies the security contract\n');
