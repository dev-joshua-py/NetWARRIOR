src = open('netwarrior.py', encoding='utf-8').read()

# Fix the broken check_deps indentation
bad = '''    _deps = ["rich", "scapy", "psutil", "paramiko", "dns", "aiohttp", "tomli", "tomli_w"]
if _sys.platform != "win32":
    _deps.append("uvloop")
for pkg in _deps:'''

good = '''    _deps = ["rich", "scapy", "psutil", "paramiko", "dns", "aiohttp", "tomli", "tomli_w"]
    if _sys.platform != "win32":
        _deps.append("uvloop")
    for pkg in _deps:'''

src = src.replace(bad, good)
open('netwarrior.py', 'w', encoding='utf-8').write(src)
print('Fixed. Run: python netwarrior.py')
