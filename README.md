# AntyVirus

Wielowarstwowy silnik detekcji zagrożeń: sygnatury, YARA, heurystyka strukturalna PE,
analiza entropii, heurystyka skryptów — z monitoringiem w czasie rzeczywistym,
kwarantanną i panelem WWW.

```
./setup.sh              # instalacja + przykładowe pliki + bazy sygnatur
./avy serve             # panel WWW: http://localhost:8080
./avy scan ~/Pobrane    # skan z wiersza poleceń
```

---

## Uczciwe ostrzeżenie

Ten projekt **nie jest zamiennikiem komercyjnego antywirusa** i nie dorównuje Avastowi,
Bitdefenderowi czy Kasperskiemu. Te produkty wykrywają ~99% świeżych próbek, bo mają
coś, czego nie da się odtworzyć w jednym repozytorium:

| Mają oni | My |
|---|---|
| sygnatury miliardów próbek | bazy społecznościowe (~16,7 tys. reguł YARA) |
| chmurowy ML na telemetrii z miliardów urządzeń | heurystyka statyczna |
| sterowniki kernelowe + sandboxing behawioralny | monitoring zdarzeń w systemie plików |
| setki analityków malware 24/7 | — |

**Do czego więc się nadaje:** do nauki, audytu podejrzanych plików, jako druga opinia
obok właściwego AV, jako silnik do skanowania przesyłek w laboratorium. Na znanym
malware i klasycznych technikach działa skutecznie; na nowym, celowanym malware
„szyte na miarę” — nie zadziała, bo nie ma go w żadnej bazie.

**Nigdy nie wyłączaj systemowego antywirusa na rzecz tego silnika.**

---

## Architektura

Sześć warstw. Każda dokłada punkty do wspólnego wyniku ryzyka (0–100):

| # | Warstwa | Co robi | Waga trafienia |
|---|---|---|---|
| 1 | **Reputacja haszowa** | md5 / sha1 / sha256 vs baza IOC, import-hash, ssdeep | 100 (decydujące) |
| 2 | **Sygnatury ClamAV** | skróty (.hdb/.hsb/.hsu) + wzorce bajtowe (.ndb) | 100 (decydujące) |
| 3 | **Reguły YARA** | bazy społecznościowe + wbudowane, z modułem `pe` | 0–60 wg klasyfikacji |
| 4 | **Heurystyka PE** | struktura plików wykonywalnych Windows | 3–35 |
| 5 | **Entropia** | pakowanie, kryptory, kompresja | 8–25 |
| 6 | **Skrypty i makra** | PowerShell / JS / VBS / BAT / makra Office | 8–45 |

**Werdykt:** `≥25 pkt` → podejrzany, `≥60 pkt` → złośliwy. Pojedyncze trafienie
krytyczne (znany hasz, sygnatura malware) daje od razu „złośliwy”, nawet gdy suma
jest niska — znany wirus nie może zostać zaklasyfikowany jako „podejrzany”.

### Krótki przebieg skanu

```
plik → typ po magii (nie po rozszerzeniu!) → hasze → PE? → warstwy 1..6 → wynik
                                                              ↓
                                              ≥ progu → kwarantanna + zdarzenie
```

Short-circuit: po trafieniu wartym 100 pkt pozostałe warstwy są pomijane — nie ma
sensu analizować pliku, który już został rozpoznany.

---

## Dlaczego reguły YARA są klasyfikowane (najważniejsza decyzja projektowa)

Publiczne bazy reguł zawierają trzy zupełnie różne rodzaje reguł. Potraktowanie ich
jednakowo kończy się lawiną fałszywych alarmów — w testach zwykły plik PE dostawał
100 punktów za same reguły `IsPE32`, `Microsoft_Visual_Cpp_8`, `contains_base64`,
`domain`.

Dlatego każda reguła jest klasyfikowana (po metadanych, nazwie i ścieżce pliku):

| Kategoria | Przykłady | Punkty |
|---|---|---|
| `malware` | `apt_*`, `gen_mal_*`, `crim_*`, reguły z katalogu `malware/` | **40** (HIGH) |
| `exploit` | `expl_*`, `CVE*` | 30 |
| `suspicious` | `anti_dbg`, `capa_*`, `gen_susp_*` | 8 |
| `unknown` | niezaklasyfikowane | 6 |
| `info` | `IsPE32`, `UPX`, `contains_base64`, `domain`, kompilatory | **0** |

Dodatkowo **słabe sygnały nie mogą same skazać pliku**: suma punktów z reguł o wadze
< 30 jest ograniczona do 20. Sterta „podejrzanych możliwości” da co najwyżej werdykt
„podejrzany”, nigdy „złośliwy”.

Aktualny rozkład załadowanych reguł: ~5 000 malware / 193 exploit / 214 suspicious /
1 700 unknown / 9 600 info.

---

## Wykrywane techniki (warstwa heurystyczna)

**Struktura PE** — entry point w ostatniej lub zapisywalnej sekcji, poza sekcjami,
albo = 0; sekcje W+X; brak sekcji `.text`; `SizeOfRawData = 0` przy dużej pamięci
wirtualnej; sekcje packerów (UPX, ASPack, Themida, VMProtect, Petite…); usunięte
relokacje; TLS callbacks; overlay i dołączony w nim drugi nagłówek MZ; zła suma
kontrolna; podejrzane/wyzerowane daty kompilacji; brak importów lub tylko
`LoadLibrary`/`GetProcAddress`; importy po numerach porządkowych; zasoby o wysokiej
entropii; brak podpisu Authenticode.

**Importy grupowane po intencji** — wstrzykiwanie kodu, process hollowing, keylogger,
ransomware (szyfrowanie + usuwanie kopii), persistence, anti-debug, kanał C2,
podnoszenie uprawnień, wyliczanie procesów.

**Entropia** — cały plik, per sekcja, w oknach (wykrywa zaszyfrowany blok wewnątrz
dużego pliku) oraz test kompresowalności (dane zaszyfrowane nie kompresują się).

**Skrypty** — PowerShell (`-enc`, `Invoke-Expression`, `DownloadString`, bypass AMSI,
wyłączanie Defendera, `Invoke-Mimikatz`), BAT (`certutil`, `bitsadmin`, usuwanie
kopii w tle, `bcdedit`, wyłączanie AV), JS/VBS (ActiveX, `eval`, `unescape`),
makra Office (`AutoOpen`, `Shell`, pobieranie), długie ciągi Base64 / hex, URL-e
zamiast nazw domenowych.

---

## Instalacja

```bash
./setup.sh
```

albo ręcznie:

```bash
pip install -r requirements.txt          # yara-python (z libyara), pefile, ppdeep, fastapi, watchdog
python3 tools/make_samples.py            # nieaktywne pliki testowe
python3 avy update                       # reguły YARA z GitHub (~16,7 tys. reguł)
```

Wymagania: Python ≥ 3.9, `git` (do aktualizacji baz). Działa na Linuksie i Windows
(analiza plików PE jest niezależna od platformy).

---

## Użycie

### Wiersz poleceń

```bash
./avy status                        # stan silnika i baz
./avy scan ~/Pobrane                # skan katalogu
./avy scan ~/Pobrane --json         # wynik maszynowy (do potoków / SIEM)
./avy file podejrzany.exe           # pełny raport dla jednego pliku
./avy info plik                     # hasze, entropia, sekcje PE (bez skanowania)
./avy update                        # aktualizacja reguł YARA
./avy realtime --paths ~/Pobrane    # ochrona w czasie rzeczywistym
./avy quarantine list               # kwarantanna
./avy quarantine restore <id>       # przywróć plik
./avy ioc add podejrzany.exe Nazwa  # dodaj własny wskaźnik
./avy serve --port 8080             # panel WWW
```

`avy scan` zwraca kod 1, gdy wykryto coś złośliwego — nadaje się do skryptów i CI.

### Panel WWW

```bash
./avy serve            # http://localhost:8080
```

Zakładki: **Pulpit** (stan, szybkie akcje, zdarzenia), **Skanowanie** (ścieżka,
przeglądarka katalogów, postęp na żywo, wyniki z dowodami), **Wykrycia** (historia
z filtrem), **Kwarantanna** (przywracanie i usuwanie), **Sygnatury** (źródła,
aktualizacja, dodawanie IOC), **Ustawienia** (progi, wątki, izolacja).

API REST (dokumentacja pod `/api/docs`): `/api/status`, `/api/scan`,
`/api/scan/{job}`, `/api/detections`, `/api/events`, `/api/quarantine`,
`/api/sigs/update`, `/api/realtime`, `/api/config`.

### Jako biblioteka

```python
from avengine import Engine, Config

cfg = Config()
cfg.malicious_threshold = 50          # bardziej surowo
engine = Engine(cfg)
engine.load()                         # ładuje sygnatury (YARA ~6 s, ~130 MB)

result = engine.scan_file("podejrzany.exe")
print(result.verdict, result.score)
for f in result.findings:
    print(f"{f.severity:8s} +{f.weight:<3} {f.detector}/{f.rule}: {f.description}")
```

---

## Bazy sygnatur

Domyślne źródła (klonowane przez `git` do `data/sigs/yara/`):

| Źródło | Reguł |
|---|---|
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | 566 plików |
| [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base) | 752 plików |

Dodaj własne w `Config.signature_sources` — każde źródło leży w osobnym katalogu,
więc jeden zepsuty feed nie psuje reszty.

**ClamAV:** wrzuć pliki `.hdb` / `.hsb` / `.hsu` / `.imp` / `.ndb` lub cały kontener
`.cvd` do `data/sigs/` — zostaną wczytane przy starcie. Obsługiwany jest pełny
podzbiór składni wzorców (`??`, `(aa|bb)`, `[00-0f]`, `{2-4}`, `*`, kotwiczenie po
offsetcie). Nieobsługiwane: `.cbc` i `.ldb` (wymagają wirtualnej maszyny bajtkowej
ClamAV) — są odnotowywane jako pominięte.

**Własne IOC:** pliki w `data/sigs/hashlists/` w formacie `hash:nazwa` albo CSV
`sha256,md5,sha1,nazwa` (styl MalwareBazaar), lub przez `avy ioc add`.

---

## Kwarantanna

Plik jest **przenoszony** (nie kopiowany) do `data/quarantine/<sha256>.quar`, a obok
powstaje `<sha256>.json` z oryginalną ścieżką, werdyktem i powodem. Przywrócenie
(„Przywróć” w panelu lub `avy quarantine restore`) wraca na to samo miejsce.

> **Uwaga praktyczna:** domyślnie skan przenosi złośliwe pliki do kwarantanny, więc
> `avy scan samples/` zabierze Ci przykładowe pliki. Odznaczenie opcji
> „izoluj wykryte zagrożenia” w panelu (lub `avy quarantine restore`) przywraca je.

---

## Wydajność

Zmierzone na ~1 300 plikach reguł YARA:

| Operacja | Wynik |
|---|---|
| Ładowanie sygnatur | ~6 s, **129 MB** RSS |
| YARA na plik | ~12 ms (4 obiekty reguł zamiast 1 300) |
| Skan katalogu | równolegle, wątki (domyślnie 8) |

Kluczowa optymalizacja: reguły kompilowane są **wsadowo** do czterech obiektów
(po walidacji każdego pliku z osobna), a nie każdy plik do osobnego obiektu.
To samo dało spadek pamięci z 734 MB do 129 MB i 3× szybsze dopasowanie.
Dodatkowo: short-circuit po trafieniu decydującym, prefiltr po prefiksach bajtowych
w sygnaturach ClamAV, strumieniowe haszowanie dużych plików.

---

## Testy

```bash
python3 -m unittest discover -s tests -v
```

24 testy: parser sygnatur ClamAV (składnia, wildcardy, dopasowanie), entropia,
werdykty dla próbek, kwarantanna (przeniesienie + przywrócenie), rozpoznawanie typów,
**klasyfikacja reguł YARA** (reguły informacyjne nie punktują) oraz test
„czysty plik PE pozostaje czysty” przy załadowanych pełnych bazach społecznościowych.

`tools/make_samples.py` tworzy nieaktywne pliki testowe (EICAR, syntetyczny PE z
cechami packera, skrypt droppujący, skrypt ransomware). Nie uruchamiaj ich —
nie zawierają działającego kodu, ale mają strukturę typową dla malware.

---

## Struktura

```
avengine/
├── engine.py              # orkiestracja warstw, skan równoległy
├── config.py  storage.py  # konfiguracja, historia w SQLite
├── quarantine.py  realtime.py
├── models.py  hashing.py  entropy.py  filetype.py
├── detectors/
│   ├── signature.py       # 1. reputacja haszowa
│   ├── clamav_sig.py      # 2. sygnatury ClamAV
│   ├── yara_layer.py      # 3. YARA + klasyfikacja reguł
│   ├── pe_heuristics.py   # 4. struktura PE
│   ├── packer.py          # 5. entropia
│   └── script_heuristics.py  # 6. skrypty i makra
├── sigs/  store.py  clamav.py  updater.py
├── cli.py                 # `avy`
└── web/  app.py  static/
tools/make_samples.py  tests/  samples/
```

## Ograniczenia

* Brak analizy behawioralnej (silnik nie uruchamia plików w piaskownicy).
* Brak heurystyki pamięci/procesów i sterownika kernelowego (to wymaga uprawnień
  SYSTEM i podpisanych sterowników).
* Brak odpakowywania archiwów (`scan_archives` jest w konfiguracji, ale warstwa
  jeszcze nie zagląda do środka ZIP/RAR).
* Bazy społecznościowe są darmowe, więc też widoczne dla autorów malware —
  wykrywają to, co już znane.

## Licencja

MIT. Projekt edukacyjny i diagnostyczny.
