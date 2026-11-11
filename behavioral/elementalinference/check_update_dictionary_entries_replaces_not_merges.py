"""update-dictionary-entries-replaces-not-merges."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-dictionary-entries-replaces-not-merges"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDictionary replaces the entries payload wholesale; the old entries do not survive alongside the new ones."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-dict-")
    dict_id = ei.create_dictionary(name=name, language="eng", entries='[{"content": "offside"}, {"content": "icing"}]')["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=dict_id))
    _wait_available(ctx, ei, dict_id)

    ei.update_dictionary(id=dict_id, entries='[{"content": "power play"}, {"content": "hat trick"}]')

    exported = ei.export_dictionary_entries(id=dict_id)
    got_contents = {e["content"] for e in json.loads(exported["entries"])}
    assert "power play" in got_contents, f"expected updated entry 'power play', got {got_contents!r}"
    assert "hat trick" in got_contents, f"expected updated entry 'hat trick', got {got_contents!r}"
    assert "offside" not in got_contents, f"stale entry 'offside' survived the update, got {got_contents!r}"
    assert "icing" not in got_contents, f"stale entry 'icing' survived the update, got {got_contents!r}"


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_available(ctx, ei, dict_id: str, cap_s: float = 90.0) -> None:
    """Poll GetDictionary every 2 s, within the run's remaining time, while it is CREATING; require AVAILABLE."""
    deadline = time.monotonic() + _budget_s(ctx, cap_s)
    status = None
    while time.monotonic() < deadline:
        status = ei.get_dictionary(id=dict_id)["status"]
        if status == "AVAILABLE":
            return
        if status != "CREATING":
            break
        time.sleep(2)
    if status == "CREATING" and _budget_spent(ctx):
        raise TimeoutError(f"dictionary {dict_id} reaching AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"dictionary {dict_id} never reached AVAILABLE before the update; last status {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
