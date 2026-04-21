#!/usr/bin/env node
/**
 * Generate kdbxweb-written KDBX4 fixtures using kdbxweb + native argon2.
 *
 * kdbxweb is the open-source library KeeWeb itself uses. Files produced
 * here are byte-for-byte representative of what KeeWeb.app would write
 * given the same inputs — the `<Generator>` metadata field is set to
 * "KeeWeb" explicitly.
 *
 * Writes fixtures + sidecars into tests/fixtures/keeweb/.
 */

'use strict';

const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const argon2 = require('argon2');
const kdbxweb = require('kdbxweb');

// -----------------------------------------------------------------------------
// Argon2 adapter — kdbxweb calls a configurable function; we delegate to the
// native `argon2` npm package. kdbxweb's type IDs: 0 = Argon2d, 2 = Argon2id.
// -----------------------------------------------------------------------------

// kdbxweb's argon2 signature (see kdbxweb source):
//   argon2(password, salt, memory, iterations, length, parallelism, type, version)
// where `memory` is already expressed in KiB (kdbxweb divides by 1024 first).
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memoryKiB, iterations, length, parallelism, type, _version) => {
  const hashType = type === 0 ? argon2.argon2d : argon2.argon2id;
  const buf = await argon2.hash(Buffer.from(password), {
    raw: true,
    salt: Buffer.from(salt),
    memoryCost: Math.max(1024, memoryKiB),    // argon2 npm rejects < 1024 KiB
    timeCost: iterations,
    parallelism,
    hashLength: length,
    type: hashType,
  });
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
});

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const OUT_DIR = path.resolve(__dirname, '..', 'kdbxweb');
const ATT_DIR = path.resolve(__dirname, '..', 'attachments');

/** Set KDF to fast-but-valid Argon2 params (keeps test runtime short). */
function setFastArgon2(db) {
  const kdf = db.header.kdfParameters;
  // I = iterations (2 is the minimum per Argon2 spec)
  kdf.set('I', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(2, 0));
  // M = memory in bytes (kdbxweb divides by 1024 before passing to argon2).
  // argon2 npm requires >= 1024 KiB, so set 1 MiB = 1048576 bytes.
  kdf.set('M', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(1024 * 1024, 0));
  // P = parallelism
  kdf.set('P', kdbxweb.VarDictionary.ValueType.UInt32, 1);
}

function addEntry(db, group, title, username, url, password, notes, tags) {
  const e = db.createEntry(group);
  e.fields.set('Title', title);
  e.fields.set('UserName', username);
  e.fields.set('URL', url);
  e.fields.set('Password', kdbxweb.ProtectedValue.fromString(password));
  if (notes) e.fields.set('Notes', notes);
  if (tags && tags.length) e.tags = tags;
  return e;
}

async function writeSidecar(filePath, data) {
  const sidecarPath = filePath.replace(/\.kdbx$/, '.json');
  const keys = Object.keys(data).sort();
  const ordered = {};
  for (const k of keys) ordered[k] = data[k];
  await fs.writeFile(sidecarPath, JSON.stringify(ordered, null, 2) + '\n', 'utf8');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// -----------------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------------

async function genKeewebBasic() {
  const name = 'kdbx4-basic';
  const pw = 'test-keeweb-201';

  const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(pw));
  const db = kdbxweb.Kdbx.create(cred, 'kdbxweb Basic Fixture');
  // kdbxweb hardcodes generator to "KdbxWeb" during save.
  setFastArgon2(db);

  const root = db.getDefaultGroup();
  const work = db.createGroup(root, 'Work');
  const pers = db.createGroup(root, 'Personal');

  const entries = [];
  entries.push(addEntry(db, work, 'Contoso Mail', 'alice@example.com',
    'https://mail.contoso.example', 'p4ss-kw-01', 'Primary work email.', ['work', 'email']));
  entries.push(addEntry(db, work, 'Fabrikam VPN', 'bob@example.org',
    'https://vpn.fabrikam.example', 'p4ss-kw-02', '', ['work', 'vpn']));
  entries.push(addEntry(db, pers, 'Acme Banking', 'charlie@example.net',
    'https://bank.acme.example', 'p4ss-kw-03', '', ['personal', 'banking']));
  entries.push(addEntry(db, pers, 'Tailspin Toys', 'dave@example.com',
    'https://toys.tailspin.example', 'p4ss-kw-04', '', ['personal']));

  const buf = await db.save();
  const outPath = path.join(OUT_DIR, `${name}.kdbx`);
  await fs.mkdir(OUT_DIR, { recursive: true });
  await fs.writeFile(outPath, Buffer.from(buf));

  await writeSidecar(outPath, {
    description: 'KDBX4 vault written by kdbxweb (the library KeeWeb.app bundles). Generator metadata is "KdbxWeb" (kdbxweb hardcodes this during save).',
    format: 'KDBX4',
    source: 'kdbxweb (node)',
    generated_by: 'tests/fixtures/.node/gen-kdbxweb.js',
    master_password: pw,
    key_file: null,
    database_name: 'kdbxweb Basic Fixture',
    generator: 'KdbxWeb',
    entry_count: 4,
    // kdbxweb auto-creates a "Recycle Bin" group; total = root + bin + 2 custom.
    group_count: 4,
    group_paths: ['/Personal', '/Recycle Bin', '/Work'],
    entries: entries.map(e => ({
      title: e.fields.get('Title'),
      username: e.fields.get('UserName'),
      url: e.fields.get('URL'),
      tags: Array.isArray(e.tags) ? [...e.tags].sort() : [],
    })).sort((a, b) => a.title.localeCompare(b.title)),
  });
  console.log(`wrote kdbxweb/${name}`);
}

async function genKeewebAttachments() {
  const name = 'kdbx4-attachments';
  const pw = 'test-keeweb-202';

  const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(pw));
  const db = kdbxweb.Kdbx.create(cred, 'kdbxweb Attachments Fixture');
  // kdbxweb hardcodes generator to "KdbxWeb" during save.
  setFastArgon2(db);

  const attSpecs = [
    ['hello.txt', 'Small Text'],
    ['1x1.png', 'Small Image'],
    ['10kib.bin', 'Medium Binary'],
    ['100kib.bin', 'Larger Binary'],
    ['empty.dat', 'Empty'],
    ['unicode-café.txt', 'Non-ASCII Filename'],
  ];

  const root = db.getDefaultGroup();
  const attMeta = [];
  for (const [fname, title] of attSpecs) {
    const data = await fs.readFile(path.join(ATT_DIR, fname));
    const entry = db.createEntry(root);
    entry.fields.set('Title', title);
    entry.fields.set('UserName', 'alice@example.com');
    entry.fields.set('URL', 'https://example.com');
    entry.fields.set('Password', kdbxweb.ProtectedValue.fromString('p4ss-kw-att'));
    // createBinary returns a Promise<{hash, value}>; that object IS the entry
    // binary reference (not a ProtectedValue). Pass the raw ArrayBuffer.
    const binRef = await db.createBinary(data.buffer.slice(
      data.byteOffset, data.byteOffset + data.byteLength,
    ));
    entry.binaries.set(fname, binRef);
    attMeta.push({
      entry: title,
      filename: fname,
      size: data.length,
      sha256: sha256Hex(data),
    });
  }

  const buf = await db.save();
  const outPath = path.join(OUT_DIR, `${name}.kdbx`);
  await fs.writeFile(outPath, Buffer.from(buf));

  await writeSidecar(outPath, {
    description: 'KDBX4 with varied attachments (text, PNG, binary, empty, non-ASCII filename). Written by kdbxweb.',
    format: 'KDBX4',
    source: 'kdbxweb (node)',
    generated_by: 'tests/fixtures/.node/gen-kdbxweb.js',
    master_password: pw,
    key_file: null,
    database_name: 'kdbxweb Attachments Fixture',
    generator: 'KdbxWeb',
    entry_count: attSpecs.length,
    // Root + auto-created Recycle Bin
    group_count: 2,
    attachments: attMeta.sort((a, b) => a.filename.localeCompare(b.filename)),
  });
  console.log(`wrote kdbxweb/${name}`);
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

(async () => {
  try {
    await genKeewebBasic();
    await genKeewebAttachments();
    console.log('done');
  } catch (e) {
    console.error('FAILED:', e);
    process.exit(1);
  }
})();
