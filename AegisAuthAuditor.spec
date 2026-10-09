from pathlib import Path

base = Path(SPECPATH)

a = Analysis(
    [str(base / "main.py")],
    pathex=[str(base)],
    binaries=[],
    datas=[(str(base / "assets" / "aegis.ico"), "assets")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AegisAuthAuditor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(base / "assets" / "aegis.ico"),
)
