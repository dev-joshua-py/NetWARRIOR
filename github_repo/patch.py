src = open('netwarrior.py', encoding='utf-8').read()

src = src.replace(
    'import uvloop',
    'import sys as _sys\nif _sys.platform != "win32":\n    import uvloop\n    _UVLOOP = True\nelse:\n    _UVLOOP = False'
)

src = src.replace(
    'for pkg in ["rich", "scapy", "psutil", "paramiko", "dns", "aiohttp", "tomli", "tomli_w", "uvloop"]:',
    '_deps = ["rich", "scapy", "psutil", "paramiko", "dns", "aiohttp", "tomli", "tomli_w"]\nif _sys.platform != "win32":\n    _deps.append("uvloop")\nfor pkg in _deps:'
)

src = src.replace(
    '    uvloop.install()\n    try:\n        asyncio.run(main())',
    '    if _UVLOOP:\n        uvloop.install()\n    try:\n        asyncio.run(main())'
)

open('netwarrior.py', 'w', encoding='utf-8').write(src)
print('Done. Run: python netwarrior.py')
