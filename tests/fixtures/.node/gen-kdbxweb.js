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

async function genKeewebChaCha20() {
  const name = 'kdbx4-chacha20';
  const pw = 'test-keeweb-203';

  const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(pw));
  const db = kdbxweb.Kdbx.create(cred, 'kdbxweb ChaCha20 Fixture');
  // Switch outer cipher from default AES-256-CBC to ChaCha20.
  db.header.dataCipherUuid = new kdbxweb.KdbxUuid(kdbxweb.Consts.CipherId.ChaCha20);
  setFastArgon2(db);

  const root = db.getDefaultGroup();
  const work = db.createGroup(root, 'Work');
  const pers = db.createGroup(root, 'Personal');

  const entries = [];
  entries.push(addEntry(db, work, 'Contoso Mail', 'alice@example.com',
    'https://mail.contoso.example', 'p4ss-cc-01', 'Primary work email.', ['work', 'email']));
  entries.push(addEntry(db, work, 'Fabrikam VPN', 'bob@example.org',
    'https://vpn.fabrikam.example', 'p4ss-cc-02', '', ['work', 'vpn']));
  entries.push(addEntry(db, pers, 'Acme Banking', 'charlie@example.net',
    'https://bank.acme.example', 'p4ss-cc-03', '', ['personal', 'banking']));
  entries.push(addEntry(db, pers, 'Tailspin Toys', 'dave@example.com',
    'https://toys.tailspin.example', 'p4ss-cc-04', '', ['personal']));

  const buf = await db.save();
  const outPath = path.join(OUT_DIR, `${name}.kdbx`);
  await fs.mkdir(OUT_DIR, { recursive: true });
  await fs.writeFile(outPath, Buffer.from(buf));

  await writeSidecar(outPath, {
    description: 'KDBX4 vault written by kdbxweb with ChaCha20 as the outer cipher (default is AES-256-CBC; overridden via db.header.dataCipherUuid). Independently-produced fixture for the ChaCha20 save/unlock round-trip.',
    format: 'KDBX4',
    source: 'kdbxweb (node)',
    generated_by: 'tests/fixtures/.node/gen-kdbxweb.js',
    master_password: pw,
    key_file: null,
    database_name: 'kdbxweb ChaCha20 Fixture',
    generator: 'KdbxWeb',
    outer_cipher: 'ChaCha20',
    entry_count: 4,
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

async function genKeewebArgon2dP8() {
  // Real-world KDBX vaults sometimes pin Argon2 parallelism to a high value
  // (commonly P=8 — KeePassXC's auto-tuner emits this on multicore machines).
  // The unlock pipeline must thread parallelism through to the `argon2`
  // crate correctly; an earlier revision derived a different transformed
  // key for P=8 vaults than the reference implementation, surfacing as a
  // spurious "wrong key" on real-world Argon2d/P=8 files. This fixture is
  // an independently-produced (kdbxweb → npm `argon2`) regression guard.
  const name = 'kdbx4-argon2d-p8';
  const pw = 'test-kdbxweb-argon2d-p8-204';

  const cred = new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(pw));
  const db = kdbxweb.Kdbx.create(cred, 'kdbxweb Argon2d P=8 Fixture');
  // kdbxweb defaults the KDBX4 KDF to Argon2d. Pin the UUID explicitly so
  // an upstream default flip wouldn't silently switch the fixture to
  // Argon2id (the variant we're specifically *not* testing here).
  const kdf = db.header.kdfParameters;
  const ARGON2D_UUID_BYTES = Buffer.from([
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b,
    0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
  ]);
  kdf.set('$UUID', kdbxweb.VarDictionary.ValueType.Bytes,
    ARGON2D_UUID_BYTES.buffer.slice(
      ARGON2D_UUID_BYTES.byteOffset,
      ARGON2D_UUID_BYTES.byteOffset + ARGON2D_UUID_BYTES.byteLength,
    ));
  kdf.set('I', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(2, 0));
  kdf.set('M', kdbxweb.VarDictionary.ValueType.UInt64, new kdbxweb.Int64(1024 * 1024, 0));
  // P = 8 — the regression guard. argon2 npm requires P >= 1.
  kdf.set('P', kdbxweb.VarDictionary.ValueType.UInt32, 8);

  const root = db.getDefaultGroup();
  addEntry(db, root, 'Contoso Mail', 'alice@example.com',
    'https://mail.contoso.example', 'p4ss-a2d-p8-01', '', ['work']);

  const buf = await db.save();
  const outPath = path.join(OUT_DIR, `${name}.kdbx`);
  await fs.mkdir(OUT_DIR, { recursive: true });
  await fs.writeFile(outPath, Buffer.from(buf));

  await writeSidecar(outPath, {
    description: (
      'KDBX4 vault with Argon2d KDF and parallelism = 8. Independently '
      + 'produced via kdbxweb + native argon2; regression guard for the '
      + 'unlock pipeline threading P through to the Argon2d derivation '
      + 'correctly. Replaces the JTL.kdbx reproduction test.'
    ),
    format: 'KDBX4',
    source: 'kdbxweb (node)',
    generated_by: 'tests/fixtures/.node/gen-kdbxweb.js',
    master_password: pw,
    key_file: null,
    database_name: 'kdbxweb Argon2d P=8 Fixture',
    generator: 'KdbxWeb',
    kdf: 'Argon2d',
    kdf_parallelism: 8,
    entry_count: 1,
    group_count: 2,
    group_paths: ['/Recycle Bin'],
    entries: [{
      title: 'Contoso Mail',
      username: 'alice@example.com',
      url: 'https://mail.contoso.example',
      tags: ['work'],
    }],
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
    await genKeewebChaCha20();
    await genKeewebArgon2dP8();
    console.log('done');
  } catch (e) {
    console.error('FAILED:', e);
    process.exit(1);
  }
})();
