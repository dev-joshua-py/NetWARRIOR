src = open('netwarrior.py', encoding='utf-8').read()

# Fix bare uvloop import
bad = 'import uvloop'
good = '''import sys as _sys
if _sys.platform != "win32":
    import uvloop
    _UVLOOP = True
else:
    _UVLOOP = False'''

if bad in src:
    src = src.replace(bad, good)
    print("uvloop import patched.")
else:
    print("uvloop line not found — already patched or different format.")

# Fix uvloop.install() at bottom
bad2 = '    uvloop.install()\n    try:\n        asyncio.run(main())'
good2 = '    if _UVLOOP:\n        uvloop.install()\n    try:\n        asyncio.run(main())'

if bad2 in src:
    src = src.replace(bad2, good2)
    print("uvloop.install() patched.")
else:
    print("uvloop.install() line not found — already patched.")

open('netwarrior.py', 'w', encoding='utf-8').write(src)
print("Done. Run: python netwarrior.py")
