// Check the real application script against a minimal form DOM.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const button = {disabled: false};
const status = {textContent: ''};
let submit;
const form = {
  addEventListener(type, handler) { assert.equal(type, 'submit'); submit = handler; },
  querySelector(selector) { return selector === 'button' ? button : status; },
};
vm.runInNewContext(readFileSync('netwatch/web/static/app.js', 'utf8'), {
  window: {setInterval() {}},
  document: {
    body: {dataset: {}},
    querySelectorAll(selector) { return selector === '[data-investigation-form]' ? [form] : []; },
  },
});
assert.equal(button.disabled, false);
submit();
assert.equal(button.disabled, true);
assert.equal(status.textContent, 'Investigating evidence…');
console.log('Investigation form progress and duplicate-submit prevention passed.');
