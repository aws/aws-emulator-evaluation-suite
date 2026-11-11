"""export-dictionary-entries-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "export-dictionary-entries-roundtrip"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExportDictionaryEntries returns the entries payload that was set at creation (content preserved,
    even if the service reformats/re-serializes the JSON)."""
    import json

    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-dict-")
    entries = [{"content": "touchdown"}, {"content": "fumble"}, {"content": "halftime"}, {"content": "quarterback sneak"}]
    dict_id = ei.create_dictionary(
        name=name, language="eng", entries=json.dumps(entries),
        tags={"Environment": "sim2real-behav"},
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=dict_id))

    exported = ei.export_dictionary_entries(id=dict_id)
    got = json.loads(exported["entries"])
    got_contents = sorted(e["content"] for e in got)
    want_contents = sorted(e["content"] for e in entries)
    assert got_contents == want_contents, f"expected {want_contents!r}, got {got_contents!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
