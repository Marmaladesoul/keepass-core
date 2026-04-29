#!/usr/bin/env node
/**
 * Generate the kdbxweb-emitted fixture used by the inner-header
 * "protected binary" regression test.
 *
 * `db.createBinary(...)` accepts both an `ArrayBuffer` (unprotected)
 * and a `kdbxweb.ProtectedValue` (protected). When the binary is a
 * `ProtectedValue`, kdbxweb's writer sets the inner-header flag byte
 * to `0x01` and writes the binary's plaintext bytes directly — the
 * same shape KeePassXC emits. Pre-fix, keepass-core ran the
 * inner-stream cipher over those plaintext bytes on read, corrupting
 * the attachment and desynchronising the keystream for every later
 * `<Value Protected="True">`.
 */
'use strict';

const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const argon2 = require('argon2');
const kdbxweb = require('kdbxweb');

kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memoryKiB, iterations, length, parallelism, type, _v) => {
  const hashType = type === 0 ? argon2.argon2d : argon2.argon2id;
  const buf = await argon2.hash(Buffer.from(password), {
    raw: true,
    salt: Buffer.from(salt),
    memoryCost: Math.max(1024, memoryKiB),
    timeCost: iterations,
    parallelism,
    hashLength: length,
    type: hashType,
  });
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
});

const OUT_DIR = path.resolve(__dirname, '..', 'kdbxweb');

(async () => {
  const pw = 'test-protected-bin-001';
  const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(pw));
  const db = kdbxweb.Kdbx.create(cred, 'kdbxweb Protected Inner Binary Fixture');
  const kdf = db.header.kdfParameters;
  kdf.set('I', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(2, 0));
  kdf.set('M', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(1024 * 1024, 0));
  kdf.set('P', kdbxweb.VarDictionary.ValueType.UInt32, 1);

  const root = db.getDefaultGroup();
  const entry = db.createEntry(root);
  entry.fields.set('Title', 'Protected Bin Demo');
  entry.fields.set('UserName', 'alice@example.com');
  entry.fields.set('URL', 'https://example.com');
  entry.fields.set('Password', kdbxweb.ProtectedValue.fromString('p4ss-protbin'));
  // A non-default protected custom field exercises a `<Value Protected="True">`
  // payload positioned *after* the inner-header binary in keystream order — the
  // exact shape that desynced pre-fix.
  entry.fields.set('TOTP Seed', kdbxweb.ProtectedValue.fromString('JBSWY3DPEHPK3PXP'));

  const data = Buffer.from('hello protected attachment\n', 'utf8');
  const dataAB = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  const pv = kdbxweb.ProtectedValue.fromBinary(dataAB);
  const binRef = await db.createBinary(pv);
  entry.binaries.set('demo.txt', binRef);

  const buf = await db.save();
  const outPath = path.join(OUT_DIR, 'kdbx4-protected-inner-binary.kdbx');
  await fs.writeFile(outPath, Buffer.from(buf));
  const sha = crypto.createHash('sha256').update(data).digest('hex');
  console.log(`wrote ${outPath} (sha256 of ${data.length}-byte attachment: ${sha})`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
