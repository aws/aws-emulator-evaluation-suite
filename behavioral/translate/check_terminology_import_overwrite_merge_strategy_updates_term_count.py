"""terminology-import-overwrite-merge-strategy-updates-term-count."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "terminology-import-overwrite-merge-strategy-updates-term-count"
GROUP = "state"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-importing with MergeStrategy=OVERWRITE replaces the terminology's full content: a term
    present only in the earlier import is dropped, never merged in alongside the new file's terms."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    tag_list = [{"Key": "project", "Value": "sim2real"}]

    translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nCloud,Nube\nLegacy,Antiguo\n", "Format": "CSV"},
        Tags=tag_list,
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))

    first = translate.get_terminology(Name=name)["TerminologyProperties"]
    assert first["TermCount"] == 2, f"expected 2 terms after initial import, got {first['TermCount']}"

    # The re-import's file has no "Legacy" term. If OVERWRITE actually replaced the full
    # content, "Legacy" is dropped and the count lands at 2 (Cloud + Server). A target that
    # incrementally merges instead would keep "Legacy" and land at 3 -- this is the case the
    # first import's data exists to expose.
    overwrite_resp = translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nCloud,Nube\nServer,Servidor\n", "Format": "CSV"},
        Tags=tag_list,
    )
    overwritten = overwrite_resp["TerminologyProperties"]
    assert overwritten["TermCount"] == 2, (
        f"expected OVERWRITE to drop 'Legacy' (absent from the new file) leaving 2 terms, "
        f"got {overwritten['TermCount']}"
    )

    second = translate.get_terminology(Name=name)["TerminologyProperties"]
    assert second["TermCount"] == 2, (
        f"independent read after overwrite expected 2 terms, got {second['TermCount']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
