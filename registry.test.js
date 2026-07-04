var assert = require('assert');
var R = require('./registry.js');

// categoryMeta falls back to "otro" for unknown categories
assert.strictEqual(R.categoryMeta('api_municipal').label, 'APIs municipales');
assert.strictEqual(R.categoryMeta('no-existe').label, R.CATEGORIES.otro.label);

// filterByCategory
var entries = [
  { id: 'a', category: 'api_municipal' },
  { id: 'b', category: 'camara_publica' },
  { id: 'c', category: 'api_municipal' }
];
assert.strictEqual(R.filterByCategory(entries, 'all').length, 3);
assert.strictEqual(R.filterByCategory(entries, 'api_municipal').length, 2);
assert.strictEqual(R.filterByCategory(entries, 'camara_publica').length, 1);

// countByCategory groups unknowns under "otro"
var counts = R.countByCategory([{ category: 'api_municipal' }, { category: 'raro' }]);
assert.strictEqual(counts.api_municipal, 1);
assert.strictEqual(counts.otro, 1);

console.log('registry.js: all tests passed');
