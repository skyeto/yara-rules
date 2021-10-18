# Decompress vercel/pkg packaged js scripts, look for PirateStealer malware

import yara
import re
import brotli

FILENAME = "sktskt-win.exe"

f = open(FILENAME, "rb")

content = f.read()

payload_position = int(re.search(b'var PAYLOAD_POSITION = \'(\d+)', content).group(1))
payload_size = int(re.search(b'var PAYLOAD_SIZE = \'(\d+)', content).group(1))
payload_sourcemap = content[re.search(b'//# sourceMappingURL=common\.js\.map[.\n]*},', content).end():]
compression_type = int(re.search(b',\n(\d)\n\);\n\}\)', payload_sourcemap).group(1))

r = yara.compile("MALW_JS_PirateStealer.yara")

if compression_type == 0:
    print("[info] compression disabled")
    
    m = r.match(FILENAME)
    
    if m:
        print("Detected:")
        print(m)
elif compression_type == 1:
    print("[error] payload gzip compressed, not implemented")
elif compression_type == 2:
    print("[info] payload brotli compressed")

    print("payload found at %d, size %d " % (payload_position, payload_size))

    print("extracting...")
    compressed = content[payload_position:payload_position+payload_size]

    w = open("compressed_sources", "wb")
    w.write(compressed)
    w.close()

    w = open("vfsmap.json", "wb")
    w.write(payload_sourcemap)
    w.close()

    csource_fd = open("compressed_sources", "rb")
    csource = csource_fd.read()

    siz = int(re.search(b'\[\d+,(\d+)\]', payload_sourcemap).group(1))

    w = open("decompressed_source", "wb")
    w.write(brotli.decompress(csource[0:siz]))
    w.close()

    m = r.match("decompressed_source")

    if m:
        print("Detected:")
        print(m)