import os
import zipfile

fixture_dir = "tests/fixtures"

# safe.png - create a minimal PNG (89 50 4E 47 0D 0A 1A 0A)
with open(os.path.join(fixture_dir, "safe.png"), "wb") as f:
    f.write(b"\x89PNG\r\n\x1a\n" + b"TEST PNG DATA")

# fake-image.jpg.exe - double extension with JPEG magic bytes
with open(os.path.join(fixture_dir, "fake-image.jpg.exe"), "wb") as f:
    f.write(b"\xFF\xD8\xFF" + b"FAKE JPEG DATA")

# archive-safe.zip - safe ZIP with text files
with zipfile.ZipFile(os.path.join(fixture_dir, "archive-safe.zip"), "w") as zf:
    zf.writestr("readme.txt", "Safe text file")
    zf.writestr("data.csv", "a,b,c\n1,2,3")

# archive-with-exe.zip - ZIP with executable
with zipfile.ZipFile(os.path.join(fixture_dir, "archive-with-exe.zip"), "w") as zf:
    zf.writestr("document.pdf.exe", "MZ executable data")
    zf.writestr("readme.txt", "Safe text")

# archive-nested.zip - nested ZIP
with zipfile.ZipFile(os.path.join(fixture_dir, "archive-nested.zip"), "w") as zf:
    zf.writestr("inner.zip", "")
    zf.writestr("readme.txt", "Safe text")

# corrupt.zip - corrupt ZIP (truncated)
with open(os.path.join(fixture_dir, "corrupt.zip"), "wb") as f:
    f.write(b"PK\x03\x04\x00\x00\x00\x00\x00\x00\x00\x00")

print("All fixtures created successfully")