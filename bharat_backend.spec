# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['parsers/api_server.py'],
    pathex=[],
    binaries=[],
    datas=[('parsers', 'parsers')],
    hiddenimports=['uvicorn', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'fastapi', 'starlette', 'pydantic', 'sqlite3', 'pandas', 'numpy', 'pyvis', 'networkx', 'parsers', 'parsers.api_server', 'parsers.social_interaction_comms_parsers', 'parsers.chat_social_privacy_parsers', 'parsers.heuristic_engine', 'parsers.plugin_loader', 'parsers.deep_sqlite', 'parsers.fiat_crypto_bridge', 'parsers.crypto_address_validator', 'parsers.crypto_p2p_parser', 'parsers.graph_intelligence'],
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
    upx=True,
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
    upx=True,
    upx_exclude=[],
    name='bharat_backend',
)
