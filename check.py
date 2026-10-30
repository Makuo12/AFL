# check.py
import sys, struct
from collections import Counter
from elftools.elf.elffile import ELFFile

MAX_ID = 52105  # "Total trap ids assigned" from the pass

f = open(sys.argv[1], "rb")
elf = ELFFile(f)

table = elf.get_section_by_name("__traps").data()
addrs = struct.unpack(f"<{len(table)//8}Q", table)

# Cache the bytes of every allocated, file-backed section once.
secs = []
for s in elf.iter_sections():
    if (s["sh_flags"] & 0x2) and s["sh_type"] != "SHT_NOBITS":
        secs.append((s["sh_addr"], s["sh_size"], s.data()))

def read(addr, n):
    for base, size, data in secs:
        if base <= addr < base + size:
            return data[addr - base: addr - base + n]
    return None

ids = []
not_cc = unmapped = bad_loop = out_of_range = 0
n_loop = 0

for a in addrs:
    b = read(a, 9)
    if b is None or len(b) < 5:
        unmapped += 1
        continue
    if b[0] != 0xCC:
        not_cc += 1
        continue
    if b[1:5] == b"\x90\x90\x90\x90":
        n_loop += 1
        if len(b) < 9:
            bad_loop += 1
            continue
        id_ = struct.unpack("<I", b[5:9])[0]
    else:
        id_ = struct.unpack("<I", b[1:5])[0]
    if id_ >= MAX_ID:
        out_of_range += 1
    ids.append(id_)

c = Counter(ids)
print(f"entries:            {len(addrs)}")
print(f"  loop traps:       {n_loop}")
print(f"  unmapped addr:    {unmapped}")
print(f"  not 0xcc:         {not_cc}")
print(f"  truncated loop:   {bad_loop}")
print(f"  id >= {MAX_ID}:   {out_of_range}")
print(f"distinct ids:       {len(c)}")
print(f"ids with >1 site:   {sum(1 for v in c.values() if v > 1)}")
print(f"missing ids:        {MAX_ID - len(c)}")
print("most duplicated:   ", c.most_common(5))