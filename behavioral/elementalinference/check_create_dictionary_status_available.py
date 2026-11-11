"""create-dictionary-status-available."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-dictionary-status-available"
GROUP = "state"
SERVICES = ["elementalinference"]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDictionary eventually reaches AVAILABLE (despite the HTTP 202 async signal), and GetDictionary agrees."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-dict-")
    resp = ei.create_dictionary(
        name=name, language="eng",
        entries='[{"content": "touchdown"}, {"content": "fumble"}, {"content": "halftime"}]',
        tags={"Environment": "sim2real-behav", "ManagedBy": "iac"},
    )
    dict_id = resp["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=dict_id))

    assert resp["status"] in ("AVAILABLE", "CREATING"), f"unexpected initial status {resp['status']}"
    assert resp["name"] == name, f"expected name {name!r}, got {resp['name']!r}"
    assert resp["language"] == "eng", f"expected language 'eng', got {resp['language']!r}"

    got = _poll_until(lambda: ei.get_dictionary(id=dict_id), lambda r: r["status"] == "AVAILABLE")
    assert got["status"] == "AVAILABLE", f"expected AVAILABLE, got {got['status']!r}"
    assert got["arn"] == resp["arn"], f"expected arn {resp['arn']!r}, got {got['arn']!r}"
    assert got.get("references", []) == [], f"expected no references, got {got.get('references')!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
