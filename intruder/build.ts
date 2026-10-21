/**
 * Build script: bundles the frontend and backend with esbuild and packages
 * dist/plugin_package.zip in the Caido plugin package format.
 * Run: npm run build (or bun run build)
 */
import * as esbuild from "esbuild";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { deflateRawSync, crc32 } from "node:zlib";
import manifest from "./manifest.json" with { type: "json" };

/** Minimal STORE/DEFLATE zip writer (no dependencies). */
class ZipWriter {
  private chunks: Uint8Array[] = [];
  private central: Uint8Array[] = [];
  private offset = 0;
  private count = 0;

  private u16(n: number) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, n, true);
    return b;
  }
  private u32(n: number) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, true);
    return b;
  }

  private concat(arrays: Uint8Array[]): Uint8Array {
    const len = arrays.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(len);
    let i = 0;
    for (const a of arrays) {
      out.set(a, i);
      i += a.length;
    }
    return out;
  }

  add(name: string, data: Uint8Array) {
    const crc = crc32(data) >>> 0;
    const compressed = deflateRawSync(data, { level: 9 });
    const useDeflate = compressed.length < data.length;
    const body = useDeflate ? compressed : data;
    const method = useDeflate ? 8 : 0;
    const nameBytes = new TextEncoder().encode(name);

    // 32-bit DOS time fixed to 2000-01-01 00:00:00 for reproducibility.
    const dosTime = this.u16(0);
    const dosDate = this.u16(0x2100 & 0xffff);

    const local = this.concat([
      this.u32(0x04034b50),
      this.u16(20), // version needed
      this.u16(0), // flags
      this.u16(method),
      dosTime,
      dosDate,
      this.u32(crc),
      this.u32(body.length),
      this.u32(data.length),
      this.u16(nameBytes.length),
      this.u16(0),
      nameBytes,
      body,
    ]);
    this.chunks.push(local);

    const central = this.concat([
      this.u32(0x02014b50),
      this.u16(20), // version made by
      this.u16(20), // version needed
      this.u16(0), // flags
      this.u16(method),
      dosTime,
      dosDate,
      this.u32(crc),
      this.u32(body.length),
      this.u32(data.length),
      this.u16(nameBytes.length),
      this.u16(0), // extra len
      this.u16(0), // comment len
      this.u16(0), // disk number
      this.u16(0), // internal attrs
      this.u32(0), // external attrs
      this.u32(this.offset),
      nameBytes,
    ]);
    this.central.push(central);
    this.offset += local.length;
    this.count++;
  }

  finish(): Uint8Array {
    const centralSize = this.central.reduce((a, b) => a + b.length, 0);
    const end = this.concat([
      this.u32(0x06054b50),
      this.u16(0),
      this.u16(0),
      this.u16(this.count),
      this.u16(this.count),
      this.u32(centralSize),
      this.u32(this.offset),
      this.u16(0),
    ]);
    return this.concat([...this.chunks, ...this.central, end]);
  }
}

async function main() {
  await mkdir("dist/plugin_package/frontend", { recursive: true });
  await mkdir("dist/plugin_package/backend", { recursive: true });  await esbuild.build({
    entryPoints: ["src/frontend/index.ts"],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    outfile: "dist/plugin_package/frontend/script.js",
    legalComments: "none",
  });

  await esbuild.build({
    entryPoints: ["src/backend/index.ts"],
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    outfile: "dist/plugin_package/backend/script.js",
    external: ["caido:*"],
    legalComments: "none",
  });

  const files: Array<{ name: string; data: Uint8Array }> = [
    { name: "manifest.json", data: new TextEncoder().encode(JSON.stringify(manifest, null, 2) + "\n") },
    { name: "frontend/script.js", data: new Uint8Array(await readFile("dist/plugin_package/frontend/script.js")) },
    { name: "backend/script.js", data: new Uint8Array(await readFile("dist/plugin_package/backend/script.js")) },
  ];

  const zip = new ZipWriter();
  for (const f of files) zip.add(f.name, f.data);
  await writeFile("dist/plugin_package.zip", zip.finish());
  console.log(`✅ Built dist/plugin_package.zip (${files.length} files)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
