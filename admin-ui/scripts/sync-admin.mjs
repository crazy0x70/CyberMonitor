import { copyFile, cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const demoRoot = path.resolve(__dirname, "..");
const distRoot = path.join(demoRoot, "dist");
const adminAppRoot = path.resolve(demoRoot, "../internal/server/web/admin-app");
const staleLegacyAdminPreviewRoot = path.resolve(demoRoot, "../internal/server/web/admin-preview");
const adminAssetsRoot = path.resolve(demoRoot, "../internal/server/web/admin-assets");
const adminBundleRoot = path.join(adminAssetsRoot, "assets");
const adminMarkerPath = path.join(adminAssetsRoot, "admin-marker.txt");
const adminBundleMarkerPath = path.join(adminBundleRoot, "admin-marker.txt");
const adminAssetBasePathToken = "__CM_ADMIN_ASSET_BASE_PATH__";
const legacyAdminAssetBasePath = "/admin-assets/";

async function cleanAdminAssets() {
  try {
    const entries = await readdir(adminAssetsRoot, { withFileTypes: true });
    await Promise.all(
      entries.map((entry) =>
        rm(path.join(adminAssetsRoot, entry.name), {
          force: true,
          recursive: entry.isDirectory(),
        }),
      ),
    );
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
}

await rm(adminAppRoot, { recursive: true, force: true });
// Clean stale artifacts left by the historical admin preview output directory.
await rm(staleLegacyAdminPreviewRoot, { recursive: true, force: true });
await mkdir(adminAppRoot, { recursive: true });
await mkdir(adminAssetsRoot, { recursive: true });
await cleanAdminAssets();

await cp(path.join(distRoot, "assets"), adminBundleRoot, {
  recursive: true,
  force: true,
});

const distIndexHTML = await readFile(path.join(distRoot, "index.html"), "utf8");
const patchedIndexHTML = distIndexHTML
  .replaceAll(legacyAdminAssetBasePath, adminAssetBasePathToken)
  .replace(
    "</title>",
    `</title>\n    <meta name="cm-admin-asset-base" content="${adminAssetBasePathToken}" />`,
  );

const entryMatch = patchedIndexHTML.match(/src="[^"]*assets\/([^"]+\.js)"/);
if (!entryMatch?.[1]) {
  throw new Error("Unable to locate admin entry bundle from dist/index.html");
}
const entryBundlePath = path.join(adminBundleRoot, entryMatch[1]);
const entryBundleSource = await readFile(entryBundlePath, "utf8");
const assetBaseRuntimeExpr =
  `((document.querySelector('meta[name="cm-admin-asset-base"]')?.content)||"${legacyAdminAssetBasePath}")+`;
const entryBundlePatched = entryBundleSource.replaceAll(
  `"${legacyAdminAssetBasePath}"+`,
  assetBaseRuntimeExpr,
);

if (entryBundlePatched === entryBundleSource) {
  throw new Error("Unable to patch admin entry bundle asset base");
}

await writeFile(path.join(adminAppRoot, "index.html"), patchedIndexHTML);
await writeFile(entryBundlePath, entryBundlePatched);

const bundleEntries = await readdir(adminBundleRoot, { withFileTypes: true });
await Promise.all(
  bundleEntries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".css"))
    .map(async (entry) => {
      const cssPath = path.join(adminBundleRoot, entry.name);
      const cssSource = await readFile(cssPath, "utf8");
      const cssPatched = cssSource.replaceAll(`${legacyAdminAssetBasePath}assets/`, "./");
      if (cssPatched !== cssSource) {
        await writeFile(cssPath, cssPatched);
      }
    }),
);

await writeFile(adminMarkerPath, "CyberMonitor Admin Asset\n");
await writeFile(adminBundleMarkerPath, "CyberMonitor Admin Asset\n");

console.log(`Synced React admin entry to ${adminAppRoot}`);
console.log(`Synced React admin assets to ${adminAssetsRoot}`);
