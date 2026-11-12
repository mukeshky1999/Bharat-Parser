"""Regression tests for REVIEW_FINDINGS_2 X-01 .. X-06 (NCRP sheet and Section 230 bundle)."""
import csv
import io

import pytest

from src.dossier_and_exhibits.exhibit_packager import ExhibitAndDefensePackager
from src.dossier_and_exhibits.models import RedactionTag, SensitiveMediaItem
from src.unk_triage_and_bsa_studio.freeze_deconfliction import NodalFreezeDeconflictionCenter


def _item(name="a.jpg", tag=RedactionTag.DISCLOSABLE, raw=b"BYTES", path="/x/a.jpg", **kw):
    return SensitiveMediaItem(
        canonical_path=path, file_name=name, sha256_hex="a" * 64, md5_hex="b" * 32,
        raw_bytes=raw, redaction_tag=tag, **kw,
    )


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


# ---------------- X-01 / X-06: NCRP sheet ----------------
def test_ncrp_does_not_invent_officer_station_state_or_category():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([{"account_no": "111", "ifsc": "X", "vpa": "m@y", "volume_inr": 5}])
    rows = _rows(c.generate_1930_ncrp_csv(ev, "VICTIM", "ACK-1"))
    r = dict(zip(rows[0], rows[1]))
    for col in ("State_UT", "Police_Station", "Investigating_Officer", "Crime_Category"):
        assert r[col] == "NOT_PROVIDED"
    flat = " ".join(sum(rows, []))
    assert "Verma" not in flat and "Uttar Pradesh" not in flat and "Cyber Crime PS" not in flat
    assert len(rows[0]) == 14


def test_ncrp_uses_supplied_details_and_requires_ack_number():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([{"account_no": "111", "vpa": "m@y", "volume_inr": 5}])
    out = c.generate_1930_ncrp_csv(ev, "V", "ACK", state_ut="Kerala", police_station="Town PS",
                                   investigating_officer="SI R. Nair", crime_category="UPI fraud")
    rows = _rows(out)
    r = dict(zip(rows[0], rows[1]))
    assert (r["State_UT"], r["Police_Station"], r["Investigating_Officer"]) == ("Kerala", "Town PS", "SI R. Nair")
    with pytest.raises(ValueError):
        c.generate_1930_ncrp_csv(ev, "V", "  ")


def test_ncrp_csv_quotes_commas_and_neutralises_formulas():
    c = NodalFreezeDeconflictionCenter()
    ev = c.evaluate_freeze_candidates([
        {"account_no": "=HYPERLINK(1)", "ifsc": "A,B", "vpa": "m@y", "volume_inr": 5},
    ])
    rows = _rows(c.generate_1930_ncrp_csv(ev, "V", "ACK", investigating_officer="Nair, R."))
    r = dict(zip(rows[0], rows[1]))
    assert len(rows[1]) == 14  # a comma must not add a column
    assert r["Beneficiary_Account_to_Freeze"].startswith("'=")
    assert r["Beneficiary_IFSC"] == "A,B"
    assert r["Investigating_Officer"] == "Nair, R."


# ---------------- X-05: biller matching ----------------
@pytest.mark.parametrize("vpa,expected", [
    ("francesca@ybl", False),      # contains 'cesc'
    ("accescorp@upi", False),
    ("bescom.billdesk@icici", True),
    ("irctc@upi", True),
    ("tata_power@sbi", True),
    ("someone@oksbi", False),
])
def test_utility_matching_is_whole_word(vpa, expected):
    assert NodalFreezeDeconflictionCenter.is_utility_biller(vpa, "") is expected


# ---------------- X-02 / X-03 / X-04: Section 230 bundle ----------------
def test_untagged_item_aborts_bundle_and_writes_nothing(tmp_path):
    out = tmp_path / "b"
    with pytest.raises(ValueError):
        ExhibitAndDefensePackager().package_section_230_defense_bundle(
            "C", [_item(tag=None)], str(out), anonymize_victim_identity=False)
    assert not out.exists() or not any(p.is_file() for p in out.rglob("*"))


@pytest.mark.parametrize("tag", [RedactionTag.PROTECTED_VICTIM_IDENTITY, RedactionTag.UNRELIED_PRIVATE_DATA,
                                 RedactionTag.CSAM_POCSO])
def test_every_non_disclosable_tag_is_withheld(tmp_path, tag):
    out = tmp_path / "b"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C", [_item(tag=tag, raw=b"SECRET_BYTES")], str(out), anonymize_victim_identity=False)
    blob = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    assert b"SECRET_BYTES" not in blob
    assert any("WITHHELD_NOTICE" in p.name for p in out.rglob("*"))


def test_path_traversal_in_file_name_stays_inside_bundle(tmp_path):
    out = tmp_path / "bundle"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C", [_item(name="../../ESCAPED.txt"), _item(name="..\\..\\ESC2.txt")], str(out),
        anonymize_victim_identity=False)
    assert not (tmp_path / "ESCAPED.txt").exists() and not (tmp_path.parent / "ESCAPED.txt").exists()
    for p in out.rglob("*"):
        assert str(p.resolve()).startswith(str(out.resolve()))


def test_victim_name_masked_everywhere_and_html_escaped(tmp_path):
    out = tmp_path / "b"
    ExhibitAndDefensePackager().package_section_230_defense_bundle(
        "C",
        [_item(name="Pooja Sharma <b>.jpg", tag=RedactionTag.CSAM_POCSO,
               path="/sdcard/Pooja Sharma/p.jpg", exif_metadata="Owner: pooja sharma")],
        str(out), anonymize_victim_identity=True, victim_name="Pooja Sharma")
    for p in out.rglob("*"):
        if p.is_file():
            assert "pooja sharma" not in (p.name + p.read_text(encoding="utf-8")).lower(), p.name
    html_text = (out / "Open_Case_Dossier.html").read_text(encoding="utf-8")
    assert "<b>" not in html_text


def test_anonymisation_without_victim_name_is_refused(tmp_path):
    with pytest.raises(ValueError):
        ExhibitAndDefensePackager().package_section_230_defense_bundle(
            "C", [_item()], str(tmp_path / "b"), anonymize_victim_identity=True, victim_name=None)
