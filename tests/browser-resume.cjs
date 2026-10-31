// Run the actual encrypted page pump with a disconnected stream. No browser/account required.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '..', 'FileSharer.cs'), 'utf8');
const pump = source.slice(source.indexOf('async function pump('), source.indexOf('\n/*\n  다 받았다는', source.indexOf('async function pump(')));
async function check(firstBytes) {
  const requests = [];
  const fixture = Buffer.from('abcdefghijklmnopqrstuvwxyz012345');
  const context = {
    Uint8Array,
    b64u: () => new Uint8Array(16),
    decryptChunk: async data => data,
    sleep: async () => {},
    fmt: String,
    $: () => ({style: {}}),
    fetch: async (url, options) => {
      requests.push(options.headers);
      const initial = requests.length === 1;
      let reads = 0;
      return {
        status: initial ? 200 : 206,
        headers: {get: key => ({'X-Download-Token': 'server-grant', 'X-Stream-Id': 'nonce', 'Content-Length': '32',
          'Content-Range': initial ? null : `bytes ${firstBytes}-31/32`})[key]},
        body: {getReader: () => ({read: async () => {
          if (initial) {
            if (reads++ === 0 && firstBytes) return {value: fixture.subarray(0, firstBytes)};
            throw new Error('fixture disconnect');
          }
          return reads++ === 0 ? {value: fixture.subarray(firstBytes)} : {done: true};
        }})}
      };
    }
  };
  vm.createContext(context);
  vm.runInContext(pump, context);
  const chunks = [];
  assert.equal(await context.pump('/api/download/fixture', null, chunks, {}), 32);
  assert.equal(requests.length, 2);
  assert.equal(requests[0]['X-Download-Token'], undefined);
  assert.equal(requests[1]['X-Download-Token'], 'server-grant');
  assert.equal(requests[1].Range, `bytes=${firstBytes}-`);
  assert.deepEqual(Buffer.concat(chunks), fixture);
}
(async () => {
  await check(0);
  await check(16);
  console.log('PASS: encrypted page carries grant on zero-byte and mid-stream retry');
})().catch(error => { console.error(error); process.exitCode = 1; });
