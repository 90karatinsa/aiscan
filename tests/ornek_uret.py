#!/usr/bin/env python3
"""Her tespit turunu iceren ornek 'kirli' proje uretir.

Kullanim:  python3 tests/ornek_uret.py /hedef/dizin
Sonra   :  bin/aiscan /hedef/dizin
"""

import os
import struct
import subprocess
import sys
import zlib

ZWSP, ZWNJ = chr(0x200B), chr(0x200C)


def zw(msg):
    return "".join(ZWSP if b == "0" else ZWNJ
                   for c in msg for b in format(ord(c), "08b"))


def tag(msg):
    return "".join(chr(0xE0000 + ord(c)) for c in msg)


def vs(data):
    return "".join(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + b - 16) for b in data)


def png(key, value):
    def chunk(ctype, payload):
        return (struct.pack(">I", len(payload)) + ctype + payload +
                struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"tEXt", key + b"\x00" + value)
            + chunk(b"IEND", b""))


def main(root):
    os.makedirs(root, exist_ok=True)
    for d in (".claude", "src", "docs", "varlik"):
        os.makedirs(os.path.join(root, d), exist_ok=True)

    def w(rel, body):
        with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
            fh.write(body)

    # 1) acik imza
    w("src/odeme.py",
      "# Generated with [Claude Code](https://claude.ai/code)\n"
      "#\n"
      "# Co-Authored-By: Claude <noreply@anthropic.com>\n\n"
      "def tutar_hesapla(kalemler):\n"
      "    # ... rest of the implementation remains unchanged\n"
      "    return sum(k['fiyat'] for k in kalemler)\n")

    # 2) gorunmez watermark: TAG karakterleri + sifir genislikli ikili yuk
    w("src/rapor.py",
      "def rapor_uret(veri):" + tag("uretim: model-2026") + "\n"
      "    baslik = 'Aylik Rapor'" + zw("AIWM") + "\n"
      "    return baslik\n")

    # 3) varyasyon secicileri ile emoji icine gizlenmis bayt
    w("docs/surum-notlari.md",
      "# Surum 2.1 \U0001F680" + vs(b"gizli-imza") + "\n\n"
      "Bu surumde performans iyilestirmeleri yapildi.\n")

    # 4) asistan metni sizintisi + prompt sizintisi
    w("src/yardimci.js",
      "// As an AI language model, I cannot access the file system directly.\n"
      "// Certainly! Here's the updated implementation:\n"
      "const SYSTEM = 'You are a helpful assistant that writes JavaScript';\n"
      "function bicimle(x) { return String(x); }\n")

    # 5) homoglif saldirisi (Latin kelimeye sizdirilmis Kiril harfi)
    w("src/kimlik.py",
      "GECERLI = 'admin'\n"
      "def kontrol(kullanici):\n"
      "    return kullanici == 'p" + chr(0x0430) + "ssword'\n")

    # 6) bidi kontrol karakteri (Trojan Source)
    w("src/yetki.c",
      "int yetkili(int rol) {\n"
      "    /* rol kontrolu" + chr(0x202E) + " */\n"
      "    return rol == 1;\n"
      "}\n")

    # 7) base64 icine gizlenmis imza
    import base64
    blob = base64.b64encode(b"Generated with Claude Code - internal marker").decode()
    w("src/yapilandirma.json", '{\n  "derleme": "%s"\n}\n' % blob)

    # 8) ajan arac artifactlari
    w("CLAUDE.md", "# Proje talimatlari\n\nBu projede test yazarken pytest kullan.\n")
    w(".claude/settings.json", '{"model": "claude-opus-4"}\n')
    w(".cursorrules", "Kod yazarken TypeScript kullan.\n")

    # 9) uslup / tipografi parmak izi
    w("docs/mimari.md",
      "# Mimari \U0001F680\n\n"
      "Bu — gercekten — kapsamli bir cozumdur. Let's dive into the details.\n\n"
      "It's important to note that the system leverages a robust and seamless "
      "architecture. Moreover, it delivers a comprehensive, cutting-edge experience "
      "that is not only scalable but also maintainable.\n\n"
      "✅ Hizli\n✅ Guvenli\n\U0001F680 Olceklenebilir\n")

    # 10) ikili dosya metadata'si
    with open(os.path.join(root, "varlik/logo.png"), "wb") as fh:
        fh.write(png(b"parameters", b"a corporate logo, Steps: 30, Sampler: DPM++ 2M"))
    with open(os.path.join(root, "varlik/kilavuz.pdf"), "wb") as fh:
        fh.write(b"%PDF-1.7\n1 0 obj<</Producer(ChatGPT Document Export)"
                 b"/Creator(OpenAI)>>endobj\ntrailer\n%%EOF\n")

    # 11) temiz dosyalar (yanlis pozitif kontrolu)
    w("src/matematik.py",
      "import math\n\n\n"
      "def daire_alani(r):\n"
      "    \"\"\"Yaricapi r olan dairenin alani.\"\"\"\n"
      "    return math.pi * r ** 2\n\n\n"
      "def aci_donustur(derece):\n"
      "    # sinθ hesaplarinda radyan gerekir\n"
      "    return derece * math.pi / 180\n")
    w("src/veritabani.py",
      "import sqlite3\n\n\n"
      "def baglan(yol):\n"
      "    return sqlite3.connect(yol)\n")

    # 12) git gecmisi: AI kimligiyle atilmis commit
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    def git(*a):
        subprocess.run(("git",) + a, cwd=root, capture_output=True, env=env)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Claude")
    git("config", "user.email", "noreply@anthropic.com")
    git("add", "-A")
    git("commit", "-q", "-m",
        "feat: odeme modulu eklendi\n\n"
        "\U0001F916 Generated with [Claude Code](https://claude.ai/code)\n\n"
        "Co-Authored-By: Claude <noreply@anthropic.com>")
    git("checkout", "-q", "-b", "claude/odeme-duzeltmesi")
    git("checkout", "-q", "main")

    print(f"Ornek proje olusturuldu: {root}")
    print(f"Tara: aiscan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/aiscan-ornek")
