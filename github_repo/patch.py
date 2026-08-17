import re

src = open('netwarrior.py', encoding='utf-8').read()

src = re.sub(
    r'for pkg in \[([^\]]*"uvloop"[^\]]*)\]',
    lambda m: 'for pkg in [' + m.group(1).replace(', "uvloop"', '').replace('"uvloop", ', '') + ']',
    src
)

open('netwarrior.py', 'w', encoding='utf-8').write(src)
print('Done. Run: python netwarrior.py')
