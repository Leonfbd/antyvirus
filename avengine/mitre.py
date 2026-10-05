"""Mapowanie znalezisk na techniki MITRE ATT&CK.

Po co: pojedynczy słaby sygnał („plik ma wysoką entropię") jest szumem.
Sygnały, które układają się w spójny łańcuch — dostarczenie → wykonanie →
utrwalenie → unikanie analizy → wpływ — są atakiem, nawet gdy każdy z osobna
wygląda niewinnie. To jedno z głównych narzędzi podnoszących precyzję: szum
zostaje na dole, a spójne łańcuchy idą w górę.

Mapowanie jest heurystyczne: opiera się na parze (detektor, nazwa reguły).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Pattern, Set, Tuple

# Taktyki w kolejności odpowiadającej łańcuchowi ataku (kill chain).
TACTICS = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]

TACTIC_PL = {
    "initial-access": "dostęp początkowy",
    "execution": "wykonanie",
    "persistence": "utrwalenie",
    "privilege-escalation": "podniesienie uprawnień",
    "defense-evasion": "unikanie obrony",
    "credential-access": "dostęp do poświadczeń",
    "discovery": "rozpoznanie",
    "lateral-movement": "ruch boczny",
    "collection": "zbieranie danych",
    "command-and-control": "dowodzenie i kontrola (C2)",
    "exfiltration": "eksfiltracja",
    "impact": "wpływ",
}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


# (wzorzec detektora, wzorzec reguły, technika)
# Kolejność ma znaczenie: pierwsze dopasowanie wygrywa, więc najpierw
# reguły najbardziej szczegółowe.
MAPPING: List[Tuple[str, str, Technique]] = [
    # --- dostarczenie / wykonanie ---
    ("archive", r"nested_threat",
     Technique("T1566.001", "Phishing: załącznik", "initial-access")),
    ("archive", r"path_traversal",
     Technique("T1566.001", "Phishing: załącznik", "initial-access")),
    ("archive", r"executable_inside",
     Technique("T1204.002", "Wykonanie przez użytkownika: złośliwy plik", "execution")),
    ("documents", r"macro_auto|vba_autorun",
     Technique("T1137", "Uruchamianie w aplikacjach Office", "persistence")),
    ("documents", r"macro_",
     Technique("T1137.001", "Makra Office", "execution")),
    ("documents", r"pdf_(js|openaction|launch)",
     Technique("T1204.002", "Wykonanie przez użytkownika: złośliwy plik", "execution")),
    ("documents", r"pdf_embedded",
     Technique("T1566.001", "Phishing: załącznik", "initial-access")),
    ("documents", r"dde",
     Technique("T1559", "Komunikacja międzyprocesowa", "execution")),
    ("documents", r"ole_embedded",
     Technique("T1027", "Zaciemnione pliki lub informacje", "defense-evasion")),

    # --- zaciemnianie / pakowanie ---
    (".*", r"packer_section|high_file_entropy|high_section_entropy|incompressible|high_entropy_region",
     Technique("T1027", "Zaciemnione pliki lub informacje", "defense-evasion")),
    (".*", r"obfuscation\.|encrypted_resource|encrypted_archive|unscannable",
     Technique("T1027", "Zaciemnione pliki lub informacje", "defense-evasion")),
    (".*", r"api_reflective|loader_stub|only_loader_apis|no_imports|ordinal_imports",
     Technique("T1027", "Zaciemnione pliki lub informacje", "defense-evasion")),

    # --- wstrzykiwanie / manipulacja procesami ---
    ("pe_heuristics", r"api_injection",
     Technique("T1055", "Wstrzykiwanie procesu", "defense-evasion")),
    ("pe_heuristics", r"api_hollowing",
     Technique("T1055.012", "Process hollowing", "defense-evasion")),
    ("pe_heuristics", r"entry_in_writable_section|section_wx|entry_outside_sections|tls_callback",
     Technique("T1055", "Wstrzykiwanie procesu", "defense-evasion")),

    # --- unikanie analizy ---
    ("pe_heuristics", r"api_evasion|anti_dbg|anti-debug",
     Technique("T1622", "Unikanie debugera", "defense-evasion")),
    ("script_heuristics", r"ps_amsi_bypass|ps_defender_off|bat_disable_av",
     Technique("T1562.001", "Wyłączanie narzędzi ochrony", "defense-evasion")),
    ("script_heuristics", r"ps_hidden|ps_obfusc|ps_shellcode",
     Technique("T1027", "Zaciemnione pliki lub informacje", "defense-evasion")),

    # --- utrwalanie ---
    ("startup", r".*",
     Technique("T1547.001", "Klucze autostartu / folder Startup", "persistence")),
    ("script_heuristics", r"bat_persist|ps_persist",
     Technique("T1547.001", "Klucze autostartu / folder Startup", "persistence")),
    ("script_heuristics", r"bat_schtasks|ps_schtasks|scheduled",
     Technique("T1053.005", "Zadanie harmonogramu", "persistence")),

    # --- wykonanie ---
    ("script_heuristics", r"powershell\.ps_iex|powershell\.ps_encoded|powershell\.ps_download",
     Technique("T1059.001", "PowerShell", "execution")),
    ("script_heuristics", r"powershell\.ps_",
     Technique("T1059.001", "PowerShell", "execution")),
    ("script_heuristics", r"batch\.",
     Technique("T1059.003", "Wiersz poleceń Windows", "execution")),
    ("script_heuristics", r"macro\.|vbs|js_eval|js_activex",
     Technique("T1059.005", "Visual Basic / skrypty", "execution")),
    ("script_heuristics", r".*certutil.*|.*bitsadmin.*|.*living_off_the_land.*",
     Technique("T1218", "Wykonanie przez binarki systemowe (LOLBIN)", "defense-evasion")),
    ("script_heuristics", r"ps_invoke_obf",
     Technique("T1059.001", "PowerShell", "execution")),

    # --- wpływ (ransomware) ---
    ("script_heuristics", r"bat_shadowcopy|bat_bcdedit|bat_cipher",
     Technique("T1490", "Blokowanie odtwarzania systemu", "impact")),
    ("pe_heuristics", r"api_ransomware",
     Technique("T1486", "Szyfrowanie danych dla wpływu", "impact")),

    # --- C2 / sieć ---
    ("pe_heuristics", r"api_network|hardcoded_ip_port|hardcoded_ips",
     Technique("T1071", "Protokół warstwy aplikacji: C2", "command-and-control")),
    ("script_heuristics", r"network\.raw_ip_url",
     Technique("T1071", "Protokół warstwy aplikacji: C2", "command-and-control")),
    ("script_heuristics", r"ps_download|js_download|macro_download|.*download.*",
     Technique("T1105", "Pobieranie narzędzi z zewnątrz", "command-and-control")),

    # --- poświadczenia ---
    ("script_heuristics", r"ps_cred|ps_mimikatz",
     Technique("T1003", "Zrzut poświadczeń systemu", "credential-access")),

    # --- rozpoznanie / uprawnienia ---
    ("pe_heuristics", r"api_process_enum",
     Technique("T1057", "Rozpoznanie procesów", "discovery")),
    ("pe_heuristics", r"api_privilege",
     Technique("T1548", "Nadużycie mechanizmu kontroli uprawnień", "privilege-escalation")),
    ("pe_heuristics", r"api_keylogger",
     Technique("T1056.001", "Przechwytywanie klawiatury", "collection")),

    # --- podszywanie ---
    ("process", r"masquerading",
     Technique("T1036.005", "Podszywanie: zgodna nazwa", "defense-evasion")),
    ("process", r"from_temp|deleted_binary|no_executable|encoded_command",
     Technique("T1036", "Podszywanie", "defense-evasion")),
    ("process", r"binary_infected",
     Technique("T1204.002", "Wykonanie przez użytkownika: złośliwy plik", "execution")),

    # --- rootkit / integralność ---
    ("rootkit", r"ld_preload|ld_so_preload",
     Technique("T1574.006", "Dynamic Linker Hijacking", "persistence")),
    ("rootkit", r"hidden_process|hidden_module|hidden_port",
     Technique("T1014", "Rootkit", "defense-evasion")),
    ("rootkit", r"suid|if |appinit|ifeo|wmi_subscription|lsa_package",
     Technique("T1546", "Wykonanie wyzwalane zdarzeniem", "persistence")),
    ("rootkit", r"unquoted_service|writable_service",
     Technique("T1574.009", "Przejęcie ścieżki do usługi", "persistence")),

    # --- exploity ---
    ("yara", r"exploit\..*|.*cve.*|.*CVE.*",
     Technique("T1203", "Eksploitacja dla wykonania kodu", "execution")),
]

_COMPILED: List[Tuple[Pattern, Pattern, Technique]] = [
    (re.compile(det, re.I), re.compile(rule, re.I), tech) for det, rule, tech in MAPPING
]


def map_finding(detector: str, rule: str) -> Optional[Technique]:
    """Zwraca technikę ATT&CK dla znaleziska albo None."""
    for det_re, rule_re, technique in _COMPILED:
        if det_re.match(detector) and rule_re.search(rule):
            return technique
    return None


def tactics_of(findings) -> Set[str]:
    """Zbiór taktyk pokrytych przez listę znalezisk."""
    tactics: Set[str] = set()
    for finding in findings:
        detector = getattr(finding, "detector", "")
        rule = getattr(finding, "rule", "")
        technique = map_finding(detector, rule)
        if technique:
            tactics.add(technique.tactic)
    return tactics


def techniques_of(findings) -> List[Dict[str, str]]:
    """Unikalne techniki ATT&CK z listy znalezisk (do raportu i GUI)."""
    seen: Dict[str, Dict[str, str]] = {}
    for finding in findings:
        detector = getattr(finding, "detector", "")
        rule = getattr(finding, "rule", "")
        technique = map_finding(detector, rule)
        if technique and technique.id not in seen:
            seen[technique.id] = {
                "id": technique.id,
                "name": technique.name,
                "tactic": technique.tactic,
                "tactic_pl": TACTIC_PL.get(technique.tactic, technique.tactic),
            }
    order = {tactic: idx for idx, tactic in enumerate(TACTICS)}
    return sorted(seen.values(), key=lambda t: order.get(t["tactic"], 99))


# Premia za spójny łańcuch: im więcej RÓŻNYCH taktyk, tym bardziej
# prawdopodobne, że mamy do czynienia z realnym atakiem, a nie z szumem.
# 0-1 taktyk: brak premii (pojedynczy sygnał zostaje na swoim poziomie).
CHAIN_BONUS = {0: 0, 1: 0, 2: 5, 3: 12, 4: 20, 5: 28}
CHAIN_BONUS_MAX = 32


def chain_bonus(tactic_count: int) -> int:
    if tactic_count <= 1:
        return 0
    if tactic_count >= 6:
        return CHAIN_BONUS_MAX
    return CHAIN_BONUS.get(tactic_count, CHAIN_BONUS_MAX)
