# -*- mode: python ; coding: utf-8 -*-
# Run from the project root (scripts/build_desktop_exe.ps1 does): `pathex` and the submodule collection below are what
# make PyInstaller find the src.* engines that parsers/api_server.py imports. After a build, read
# build_backend/**/warn-bharat_backend.txt for "missing module" lines naming src.* or parsers.* before shipping.
import os
import sys
from PyInstaller.utils.hooks import collect_submodules

_own_modules = collect_submodules('src') + collect_submodules('parsers')

# Python 3.15 ships python3t.dll in abi3t-compat/. Extension modules built for the stable ABI (cryptography's _rust.pyd)
# import it, and PyInstaller does not bundle it: the frozen backend then stops at "DLL load failed while importing _rust".
_extra_binaries = []
_abi3t = os.path.join(sys.base_prefix, 'abi3t-compat', 'python3t.dll')
if os.path.isfile(_abi3t):
    _extra_binaries.append((_abi3t, '.'))


a = Analysis(
    ['parsers/api_server.py'],
    pathex=['.'],
    binaries=_extra_binaries,
    datas=[('parsers', 'parsers')],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'fastapi', 'starlette', 'pydantic', 'sqlite3', 'pandas', 'numpy', 'pyvis', 'networkx', 'parsers', 'parsers.api_server', 'parsers.social_interaction_comms_parsers', 'parsers.chat_social_privacy_parsers', 'parsers.heuristic_engine', 'parsers.plugin_loader', 'parsers.deep_sqlite', 'parsers.fiat_crypto_bridge', 'parsers.crypto_address_validator', 'parsers.crypto_p2p_parser', 'parsers.graph_intelligence', 'regex'] + _own_modules,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='bharat_backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                # UPX-packed executables are often flagged by security software on lab machines
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='bharat_backend',
)
