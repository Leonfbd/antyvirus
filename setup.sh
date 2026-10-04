#!/usr/bin/env bash
# Instalacja zależności i przygotowanie środowiska.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO"

PYTHON="${PYTHON:-python3}"

echo "==> 1/4 Instalacja zależności (pip)"
"$PYTHON" -m pip install --break-system-packages -r requirements.txt 2>/dev/null \
  || "$PYTHON" -m pip install -r requirements.txt

echo "==> 2/4 Katalog danych"
mkdir -p data/sigs/yara data/sigs/hashlists data/quarantine

echo "==> 3/4 Przykładowe pliki testowe (nieaktywne)"
"$PYTHON" tools/make_samples.py

echo "==> 4/4 Aktualizacja baz sygnatur YARA (wymaga dostępu do github.com)"
"$PYTHON" avy update || echo "    (pominięto - brak sieci lub git; silnik użyje reguł wbudowanych)"

cat <<'EOF'

Gotowe. Najczęściej używane polecenia:

  ./avy status                       stan silnika i baz
  ./avy scan samples                 skanuj katalog z przykładami
  ./avy file samples/eicar.com       pełny raport dla jednego pliku
  ./avy update                       pobierz reguły YARA z GitHub
  ./avy realtime --paths ~/Pobrane   ochrona w czasie rzeczywistym
  ./avy serve --port 8080            panel WWW (http://localhost:8080)

Testy:
  python3 -m unittest discover -s tests -v
EOF
