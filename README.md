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

Dziewięć warstw. Każda dokłada punkty do wspólnego wyniku ryzyka (0–100):

| # | Warstwa | Co robi | Waga trafienia |
|---|---|---|---|
| 1 | **Reputacja haszowa** | md5 / sha1 / sha256 vs baza IOC, import-hash, ssdeep | 100 (decydujące) |
| 2 | **Sygnatury ClamAV** | skróty (.hdb/.hsb/.hsu) + wzorce bajtowe (.ndb) | 100 (decydujące) |
| 3 | **Reguły YARA** | bazy społecznościowe + wbudowane, z modułem `pe` | 0–60 wg klasyfikacji |
| 4 | **Heurystyka PE** | struktura plików wykonywalnych Windows | 3–35 |
| 5 | **Entropia** | pakowanie, kryptory, kompresja | 8–25 |
| 6 | **Skrypty i makra** | PowerShell / JS / VBS / BAT / makra Office | 8–45 |
| 7 | **Archiwa** | rozpakowanie ZIP/TAR/7z/RAR/gzip/xz i skan zawartości | 8–100 |
| 8 | **Dokumenty** | Office (OLE2 i OOXML): makra, osadzenia, DDE; PDF: JavaScript, auto-akcje | 5–45 |
| 9 | **Korelacja** | łańcuch ataku wg MITRE ATT&CK, rabat za zaufany katalog | 0–32 |
| — | **Procesy** | obrazy uruchomionych procesów, podszywanie, katalog tymczasowy | 5–50 |
| — | **Autostart** | klucze Run, usługi, harmonogram, cron, systemd, profile powłoki | 15–50 |
| — | **Integralność** | rootkity: ukryte procesy i gniazdka, ld.so.preload, AppInit, IFEO, WMI | 18–60 |

**Werdykt:** `≥25 pkt` → podejrzany, `≥60 pkt` → złośliwy. Pojedyncze trafienie
krytyczne (znany hasz, sygnatura malware) daje od razu „złośliwy”, nawet gdy suma
jest niska — znany wirus nie może zostać zaklasyfikowany jako „podejrzany”.

### Krótki przebieg skanu

```
plik → typ po magii (nie po rozszerzeniu!) → hasze → PE? → warstwy 1..6 → wynik
                                                              ↓
                                              ≥ progu → kwarantanna + zdarzenie
```

Short-circuit: po trafieniu wartym 100 pkt pomijane są **kosztowne** warstwy (YARA,
heurystyka PE, archiwa). Tanie warstwy, które dopisują kontekst (dokumenty,
korelacja), uruchamiają się nadal — dzięki temu raport tłumaczy, *co* znaleziono,
zamiast poprzestać na informacji „jest źle”.

---

## Kontrola jakości reguł: test kanarkowy i lista tłumień

Publiczne bazy reguł są darmowe i utrzymywane przez społeczność, więc trafiają
się w nich reguły zepsute. Najlepszy znaleziony przykład:

```yara
$commands         = /version|ls|cd|sysinfo|download|upload|shot|.../   // "version" ma każdy plik
$grammer_massacre = /BADD|Bad Error Happened|/                          // pusta gałąź "|" = pasuje WSZĘDZIE
condition: 3 of them
```

Końcowe `|` tworzy pustą alternatywę, która dopasowuje się do pustego ciągu —
czyli do każdego pliku. W parze z jednym trafieniem słowa „Affine" (obecnego
w bibliotekach kryptograficznych Go) reguła flagowała m.in. `/usr/bin/envd`
i `/usr/bin/sshd`.

Silnik broni się przed tym dwustopniowo, dokładnie tak jak komercyjne AV
(testowanie sygnatur na korpusie czystych plików + ręczne listy wyłączeń):

1. **Test kanarkowy (automatyczny).** Po załadowaniu każda reguła jest
   uruchamiana na zestawie próbek, na których poprawna reguła nie ma prawa
   zadziałać: dane losowe, zera, tekst z pospolitymi słowami oraz fragmenty
   prawdziwych binarek systemowych. Reguła, która się dopasuje, zostaje
   wyłączona z punktacji (0 pkt, widoczna jako adnotacja). Obecnie odpada
   7 reguł, w tym `domain`, `IP`, `contains_base64`, `url`.
2. **Lista tłumień (ręczna).** `avengine/sigs/suppressed_rules.txt` na
   przypadki, których automat nie wychwyci — każdy wpis ma opisany powód.
   Własne wpisy możesz trzymać w `data/sigs/suppressed_rules.txt`.

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

**Archiwa** — zawartość rozpakowywana jest w pamięci (lub, dla 7z/RAR, przez
katalog tymczasowy) i skanowana wszystkimi warstwami, z zagnieżdżeniem do 3
poziomów. Wykrywany jest **path traversal** (`../../etc/evil.sh`), **bomba zip**
(współczynnik kompresji sprawdzany *przed* rozpakowaniem), **zaszyfrowane
archiwa** (werdykt: nieprzebadane, nie „czyste") oraz pliki wykonywalne
ukryte pod podwójnym rozszerzeniem (`faktura.pdf.exe`).

**Procesy** — każdy uruchomiony proces jest weryfikowany: z jakiego pliku
wystartował, czy ten plik istnieje (malware kasuje swój dropper), czy nie
podszywa się pod proces systemowy (`svchost.exe` z `%TEMP%`), czy startuje
z katalogu tymczasowego, czy dostał zakodowane polecenie (`powershell -enc`)
i czy utrzymuje połączenia sieciowe. Wątki jądra nie są traktowane jako
zagrożenie (to osobna, częsta pułapka).

**Autostart** — wyliczane są wszystkie miejsca, z których system uruchamia kod
bez pytania, wraz z oceną tego, co z nich wystartuje: **osierocone wpisy**
(wskazujące na nieistniejący plik), uruchamianie z katalogów zapisywalnych
przez użytkownika, podszywanie się pod procesy systemowe oraz podejrzane
polecenia (`certutil`, `curl | sh`, `powershell -enc`).

Windows: klucze Run/RunOnce (HKCU i HKLM), Winlogon, usługi (ImagePath),
foldery Startup, zadania harmonogramu.
Linux: `~/.config/autostart`, `/etc/xdg/autostart`, crontab, jednostki
systemd (użytkownika i systemowe), `/etc/init.d`, `/etc/rc.local`,
profile powłoki.

**Skrypty** — PowerShell (`-enc`, `Invoke-Expression`, `DownloadString`, bypass AMSI,
wyłączanie Defendera, `Invoke-Mimikatz`), BAT (`certutil`, `bitsadmin`, usuwanie
kopii w tle, `bcdedit`, wyłączanie AV), JS/VBS (ActiveX, `eval`, `unescape`),
makra Office (`AutoOpen`, `Shell`, pobieranie), długie ciągi Base64 / hex, URL-e
zamiast nazw domenowych.

---

## Dokumenty: makra, osadzenia i PDF

Najczęstszy wektor infekcji nie jest już plikiem `.exe`, tylko dokumentem.
Przykładowy łańcuch: faktura `.docm` → makro `AutoOpen` → `WScript.Shell`
→ PowerShell pobierający drugi etap. Żaden element tego łańcucha nie jest
plikiem wykonywalnym, więc skaner skupiony na PE nic nie zauważy.

| Format | Co sprawdzamy |
|---|---|
| **OLE2** (`.doc`, `.xls`, `.ppt`) | strumienie VBA (`Macros/`, `_VBA_PROJECT_CUR`), osadzone obiekty `\x01Ole10Native` **z nazwą pliku**, pola DDE/DDEAUTO |
| **OOXML** (`.docm`, `.xlsm`, `.docx`) | `vbaProject.bin`, osadzenia, ActiveX, relacje zewnętrzne, zdalne szablony, `ddeLink` |
| **PDF** | `/JavaScript` + `/OpenAction` (wykonanie przy otwarciu), `/Launch`, `/EmbeddedFile`, `/URI`, XFA, ukryta treść po dekompresji strumieni FlateDecode, uszkodzona tablica xref |

Słowa kluczowe makr są grupowane po **zachowaniu**, nie po nazwie: automatyczne
uruchomienie (`Auto_Open`, `Document_Open`), uruchomienie powłoki
(`WScript.Shell`, `Shell`), pobieranie (`URLDownloadToFile`, `ADODB.Stream`),
zaciemnianie (`Chr()`, `StrReverse`), utrwalanie (`RegWrite`).

## Integralność systemu (rootkity)

Skanowanie plików nie odpowie na pytanie „czy ktoś już jest w środku”. Moduł
`integrity` konfrontuje ze sobą dwa źródła prawdy o systemie:

| Test | Na czym polega |
|---|---|
| Ukryte procesy | PID-y obecne w `/proc`, ale nieznane dla API systemowego |
| Ukryte gniazdka | inody z `/proc/net/tcp`, których nie da się przypisać do procesu |
| Ukryte moduły | `/proc/modules` vs `/sys/module` |
| `ld.so.preload` / `LD_PRELOAD` | biblioteka wstrzykiwana do każdego procesu |
| Usunięte binaria | procesy działające z plików skasowanych z dysku |
| SUID/SGID w `/tmp` | gotowy mechanizm podniesienia uprawnień |
| Konta UID 0 | dodatkowe konta o uprawnieniach roota |
| Windows | AppInit_DLLs, przejęcie IFEO (`Debugger`), subskrypcje WMI, pakiety LSA, usługi bez cudzysłowu, dodatki netsh, wyłączony Defender |

Dwie decyzje projektowe, które odróżniają ten moduł od naiwnej implementacji:

1. **Osobno oznaki włamania, osobno słaba konfiguracja.** Katalog systemowy
   zapisywalny dla wszystkich to podatność, nie dowód infekcji — trafia do
   sekcji *hartowanie* i nie podnosi werdyktu o bezpieczeństwie maszyny.
2. **Test, którego nie da się wykonać, jest pomijany, a nie zgadywany.**
   Sprawdzenie ukrytych gniazdek wymaga prawa odczytu `/proc/<pid>/fd` cudzych
   procesów. Bez uprawnień roota każde gniazdko wyglądałoby na ukryte — moduł
   wykrywa ten stan (widoczne mniej niż 50 % procesów) i pomija test,
   informując o tym w raporcie. Wcześniej dawało to cztery fałszywe alarmy.

## Korelacja: łańcuch ataku wg MITRE ATT&CK

Pojedynczy słaby sygnał to szum. Sygnały układające się w **spójny łańcuch** to
atak. Każde znalezisko dostaje identyfikator techniki (`T1055.012`, `T1486`,
`T1547.001`…), a premia rośnie wraz z liczbą *różnych taktyk*:

| Różnych taktyk | 0–1 | 2 | 3 | 4 | 5 | 6+ |
|---|---|---|---|---|---|---|
| Premia | 0 | +5 | +12 | +20 | +28 | +32 |

Dodatkowo heurystyka statystyczna dostaje **rabat w katalogach systemowych**
(`/usr/bin`, `C:\Windows\System32`) — tam ma najwyższy odsetek fałszywych
alarmów. Rabat nie dotyczy sygnatur exact-match: znany wirus jest wirusem
niezależnie od katalogu.

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
./avy processes                     # skan uruchomionych procesów
./avy startup                       # audyt miejsc autostartu
./avy integrity                     # kontrola integralności systemu (rootkity)
./avy report ~/Pobrane -o raport.html   # skan + raport HTML (lub --format json/txt)
./avy serve --port 8080             # panel WWW
```

`avy scan` zwraca kod 1, gdy wykryto coś złośliwego — nadaje się do skryptów i CI.

### Panel WWW

```bash
./avy serve            # http://localhost:8080
```

Zakładki: **Pulpit** (stan, szybkie akcje, zdarzenia), **Skanowanie** (ścieżka,
przeglądarka katalogów, postęp na żywo, wyniki z dowodami), **Wykrycia** (historia
z filtrem), **Kwarantanna** (przywracanie i usuwanie), **Procesy** i **Autostart**
(utrwalanie), **Integralność** (rootkity i słaba konfiguracja), **Sygnatury**
(źródła, aktualizacja, dodawanie IOC), **Ustawienia** (progi, wątki, izolacja).

API REST (dokumentacja pod `/api/docs`): `/api/status`, `/api/scan`,
`/api/scan/{job}`, `/api/detections`, `/api/events`, `/api/quarantine`,
`/api/sigs/update`, `/api/realtime`, `/api/config`, `/api/processes`,
`/api/startup`, `/api/integrity`, `/api/report/{job_id}?fmt=html|json|txt`.

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
| Ładowanie sygnatur | ~7 s, **129 MB** RSS |
| YARA na plik | ~12 ms (4 obiekty reguł zamiast 1 300) |
| Mały plik PE (3 KB), pełny skan | ~13 ms |
| Duży plik (12,8 MB), pełny skan | **6,8 s** (było 24 s) |
| Skan katalogu | równolegle, wątki (domyślnie 8) |

Kluczowe optymalizacje:

* Reguły YARA kompilowane **wsadowo** — 4 obiekty zamiast 1 300 (pamięć
  734 MB → 129 MB, 3× szybsze dopasowanie).
* Reguły **informacyjne** (0 pkt) pomijane na plikach > 1 MB — to one są
  najdroższe, bo pasują do wszystkiego.
* **ssdeep** (czysty Python, ~11 s dla 12 MB) liczony tylko wtedy, gdy baza
  ma hasze fuzzy do porównania.
* **Entropia z próbki** dla plików > 4 MB (wynik statystycznie identyczny,
  koszt ~20× mniejszy).
* Short-circuit po trafieniu decydującym, prefiltr po prefiksach bajtowych
  w sygnaturach ClamAV, strumieniowe haszowanie dużych plików.

---

## Testy

```bash
python3 -m unittest discover -s tests -v
```

50 testów:

* parser sygnatur ClamAV (składnia, wildcardy, dopasowanie), entropia,
  rozpoznawanie typów, kwarantanna, raporty HTML/JSON;
* **archiwa** — EICAR w ZIP, czysty ZIP zostaje czysty, path traversal, bomba
  zip, zaszyfrowane 7z (szyfrowanie = „nieprzebadane”, nie „czyste”);
* **dokumenty** — PDF z JavaScriptem i `/OpenAction`, czysty PDF zostaje czysty,
  dokument z makrem jest wykrywany *wraz z opisem zachowania*, czysty `.docx`
  zostaje czysty;
* **korelacja i MITRE** — mapowanie technik, premia za łańcuch ataku, rabat
  heurystyki w katalogach systemowych;
* **integralność** — `ld.so.preload`, ukryty proces, dodatkowe konto UID 0,
  binaria SUID w katalogu zapisywalnym oraz test *negatywny*: sprawdzenie
  ukrytych gniazdek bez uprawnień do `/proc/<pid>/fd` musi zostać pominięte,
  a nie zgłosić fałszywy alarm;
* **klasyfikacja reguł YARA** — reguły informacyjne nie punktują, lista tłumień
  jest ładowana, reguły kanarkowe są odrzucane, czysty plik PE pozostaje czysty
  przy załadowanych pełnych bazach społecznościowych.

Testy integralności używają syntetycznych katalogów (`/proc` i `/etc/passwd`
podstawione na katalogi tymczasowe) — nigdy nie dotykają prawdziwego systemu.

`tools/make_samples.py` tworzy nieaktywne pliki testowe (EICAR, syntetyczny PE z
cechami packera, skrypt droppujący, skrypt ransomware, dokument z makrem, PDF z
JavaScriptem). Nie uruchamiaj ich — nie zawierają działającego kodu, ale mają
strukturę typową dla malware.

> Uwaga praktyczna z developmentu: skanowanie katalogu `samples/` z włączoną
> kwarantanną **przenosi próbki poza katalog**. Jeśli fixture zniknie, zajrzyj do
> `data/quarantine/` (metadane w plikach `.json` zawierają oryginalną ścieżkę).

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
│   ├── script_heuristics.py  # 6. skrypty i makra
│   ├── archive.py         # 7. archiwa
│   ├── documents.py       # 8. Office (OLE2/OOXML) i PDF
│   └── correlation.py     # 9. łańcuch ataku (MITRE) i rabat za kontekst
├── mitre.py  rootkit.py   # mapowanie ATT&CK, integralność systemu
├── sigs/  store.py  clamav.py  updater.py
├── processes.py  startup_audit.py  archives.py  report.py
├── cli.py                 # `avy`
└── web/  app.py  static/
tools/make_samples.py  tests/  samples/
```

## Ograniczenia

* Brak analizy behawioralnej (silnik nie uruchamia plików w piaskownicy).
* Brak heurystyki pamięci/procesów i sterownika kernelowego (to wymaga uprawnień
  SYSTEM i podpisanych sterowników).
* Archiwa RAR wymagają zewnętrznego narzędzia (`unrar`/`bsdtar`) — bez niego
  zawartość RAR pozostaje nieprzebadana.
* Procesy są oceniane po ich obrazie na dysku, nie po zawartości pamięci
  (do analizy pamięci potrzebny jest sterownik kernelowy).
* Kontrola integralności nie wykrywa hooków jądra (SSDT/IDT) ani modyfikacji
  pamięci jądra (DKOM) — to wymaga podpisanego sterownika. Moduł wymienia te
  techniki wprost jako pozostające poza zasięgiem, żeby czysty wynik nie
  budził złudnego poczucia bezpieczeństwa.
* Część testów integralności wymaga uprawnień roota (odczyt `/proc/<pid>/fd`).
  Bez nich są pomijane — wymienione w raporcie.
* Bazy społecznościowe są darmowe, więc też widoczne dla autorów malware —
  wykrywają to, co już znane.

## Licencja

MIT. Projekt edukacyjny i diagnostyczny.
