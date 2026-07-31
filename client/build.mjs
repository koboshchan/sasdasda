// esbuild build script for the SecureCord client.
//
// Bundles src/main.ts -> dist/bundle.js and copies index.html into dist/ so
// that a single `dist/` directory (mounted read-only into the server
// container by docker-compose.yml) is enough to serve the whole app.
import * as esbuild from 'esbuild';
import { copyFileSync, mkdirSync } from 'node:fs';

const watch = process.argv.includes('--watch');

mkdirSync('dist', { recursive: true });

function copyHtml() {
  copyFileSync('index.html', 'dist/index.html');
}

const options = {
  entryPoints: ['src/main.ts'],
  bundle: true,
  outfile: 'dist/bundle.js',
  format: 'esm',
  target: 'es2022',
  sourcemap: true,
  logLevel: 'info',
  plugins: [
    {
      name: 'copy-index-html',
      setup(build) {
        build.onEnd(() => copyHtml());
      },
    },
  ],
};

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  console.log('watching for changes...');
} else {
  await esbuild.build(options);
  console.log('build complete.');
}
