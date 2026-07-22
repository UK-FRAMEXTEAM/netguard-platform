const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const extensionRoot = path.join(__dirname, '..');
const content = fs.readFileSync(path.join(extensionRoot, 'js', 'content.js'), 'utf8');
const background = fs.readFileSync(path.join(extensionRoot, 'js', 'background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'manifest.json'), 'utf8'));
const rules = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'rules.json'), 'utf8'));

test('loads the shared risk engine before the page protection script', () => {
  assert.deepEqual(manifest.content_scripts[0].js, [
    'js/config.js', 'js/risk-engine.js', 'js/content.js',
  ]);
  assert.match(background, /importScripts\('config\.js', 'risk-engine\.js'\)/);
});

test('warning contract contains blur, AI recommendation, countdown, and both decisions', () => {
  assert.match(content, /filter: blur\(8px\)/);
  assert.match(content, /NETGUARD AI RISK RECOMMENDATION/);
  assert.match(content, /Date\.now\(\) \+ 10000/);
  assert.match(content, /Go Back to Safety/);
  assert.match(content, /Continue Anyway/);
  assert.match(content, /'auto-back'/);
  assert.match(content, /'continue'/);
});

test('known threat rules still block subresources without hiding the main-page warning', () => {
  assert.ok(rules.length > 0);
  for (const rule of rules) {
    assert.ok(rule.condition.resourceTypes.includes('sub_frame'));
    assert.ok(rule.condition.resourceTypes.includes('script'));
    assert.ok(!rule.condition.resourceTypes.includes('main_frame'));
  }
});
