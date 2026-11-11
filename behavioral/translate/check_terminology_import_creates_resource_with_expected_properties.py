"""terminology-import-creates-resource-with-expected-properties."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "terminology-import-creates-resource-with-expected-properties"
GROUP = "state"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportTerminology synchronously creates an ACTIVE-equivalent resource whose properties persist."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    csv_body = b"en,es\nCloud Computing,Informatica en la nube\n"

    create_resp = translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": csv_body, "Format": "CSV"},
        Tags=[{"Key": "project", "Value": "sim2real"}],
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))

    props = create_resp["TerminologyProperties"]
    assert props["Name"] == name, f"expected Name {name!r}, got {props['Name']!r}"
    assert props["SourceLanguageCode"] == "en", (
        f"expected SourceLanguageCode 'en' derived from the CSV header, got {props['SourceLanguageCode']!r}"
    )
    assert props["TargetLanguageCodes"] == ["es"], (
        f"expected TargetLanguageCodes ['es'] derived from the CSV header, got {props['TargetLanguageCodes']!r}"
    )
    assert props["Format"] == "CSV", f"expected Format 'CSV', got {props['Format']!r}"
    assert props["TermCount"] == 1, f"expected TermCount 1 (one data row), got {props['TermCount']!r}"
    assert props["SizeBytes"] > 0, f"expected SizeBytes > 0 for a non-empty upload, got {props['SizeBytes']!r}"

    get_resp = translate.get_terminology(Name=name)
    got = get_resp["TerminologyProperties"]
    assert got["Name"] == name, f"GetTerminology: expected Name {name!r}, got {got['Name']!r}"
    assert got["SourceLanguageCode"] == "en", (
        f"GetTerminology: expected SourceLanguageCode 'en' to persist, got {got['SourceLanguageCode']!r}"
    )
    assert got["TargetLanguageCodes"] == ["es"], (
        f"GetTerminology: expected TargetLanguageCodes ['es'] to persist, got {got['TargetLanguageCodes']!r}"
    )
    assert got["TermCount"] == 1, f"GetTerminology: expected TermCount 1 to persist, got {got['TermCount']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
