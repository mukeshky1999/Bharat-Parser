# Third-party licences

Audit date: 2026-11-12. Source: package metadata installed in `.venv` and `node_modules` on the build machine.
This is an engineering inventory, not legal advice. Have the attorney confirm it before any sale or filing.

## Python (requirements.txt)

| Package | Version seen | Licence | Note |
|---|---|---|---|
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | |
| zstandard | 0.25.0 | BSD-3-Clause | |
| brotli | 1.2.1 | MIT | |
| lz4 | 4.4.5 | BSD | |
| cbor2 | 6.2.0 | MIT | |
| msgpack | 1.2.4 | Apache-2.0 | |
| protobuf | 7.36.2 | BSD-3-Clause | |
| eth-hash | 0.8.0 | MIT | |
| pytsk3 | 20260715 | Apache-2.0 | Wraps The Sleuth Kit, whose own licences are mixed. Check the licence of the bundled library before shipping. Used only for raw-image directory walking, optional import. |
| pyewf-wheels | not installed here | upstream libewf is LGPL-3.0 | Not verified in this environment. Optional import. LGPL: dynamic use is normally fine; static bundling in the .exe needs compliance (offer the library source, allow replacement). Decide before building the installer. |
| regex | 2026.11.9 | Apache-2.0 | Used for regular-expression search so one match can be stopped after a time limit. |
| fastapi | 0.162.0 | MIT | |
| uvicorn | 0.54.0 | BSD-3-Clause | |
| python-multipart | 0.0.33 | Apache-2.0 | |
| pydantic | 2.14.2 | MIT | |
| httpx | 0.28.1 | BSD-3-Clause | |
| pandas | 3.1.0 | BSD-3-Clause | |
| numpy | 2.5.4 | BSD-3-Clause and other permissive | |
| networkx | 3.7 | BSD-3-Clause | |
| pyvis | 0.3.2 | BSD | |
| openpyxl | not installed here | MIT (upstream) | Not verified locally. |
| pyyaml | 6.0.3 | MIT | |
| lxml | 6.1.3 | BSD-3-Clause | |
| pillow | not installed here | HPND (upstream) | Not verified locally. |
| psutil | 7.2.2 | BSD-3-Clause | |
| pytest | 9.2.0 | MIT | test only |
| pytest-cov | not installed here | MIT (upstream) | test only |
| pyinstaller | 6.22.3 | GPL-2.0-or-later with a bootloader exception | Build tool. The exception allows distributing the produced .exe under any licence. Not shipped inside the product. |

## JavaScript (package.json)

All 16 direct dependencies are MIT, ISC or Apache-2.0 (react, react-dom, zustand, vite, tailwindcss, electron,
electron-builder, lucide-react, typescript and the type packages).
Transitive packages in `node_modules` (about 280): MIT 217, ISC 27, BSD-2/3 15, Apache-2.0 10, BlueOak 6,
MPL-2.0 2, 0BSD 1, CC-BY-4.0 1 (`caniuse-lite`, a data file used at build time), WTFPL variants 2, Python-2.0 1.
No GPL or AGPL package was found. MPL-2.0 is file-level copyleft: fine unless we modify those files.

## Bundled with the desktop build

Electron bundles Chromium and FFmpeg. Their licences (BSD and LGPL parts) travel with the Electron distribution
(`LICENSES.chromium.html`); keep that file in the installer.

## Fonts and icons

`lucide-react` icons are ISC. No web fonts are loaded from the network.

## Open items

1. Install and record the `pyewf-wheels`, `openpyxl`, `pillow` and `pytest-cov` licences from a clean environment.
2. Decide on LGPL handling for libewf before building the installer (or drop E01 support).
3. Re-run this audit before each release; automate with `pip-licenses` and `license-checker` once approved.
