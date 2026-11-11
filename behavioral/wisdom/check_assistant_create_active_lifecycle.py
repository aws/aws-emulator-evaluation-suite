"""assistant-create-active-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "assistant-create-active-lifecycle"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssistant transitions to ACTIVE and GetAssistant reflects the fields that were set."""
    wisdom = ctx.client("wisdom")
    name = ctx.unique_name("sim2real-asst-")
    created = wisdom.create_assistant(
        name=name,
        type="AGENT",
        description="behavioral check assistant",
        tags={"simparity-check": "assistant-create-active-lifecycle"},
    )["assistant"]
    assistant_id = created["assistantId"]
    ctx.on_cleanup(lambda: wisdom.delete_assistant(assistantId=assistant_id))

    final = _poll_until(
        lambda: wisdom.get_assistant(assistantId=assistant_id)["assistant"],
        lambda a: a["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "ACTIVE", f"expected status ACTIVE, got {final['status']!r}"
    assert final["name"] == name, f"expected name {name!r}, got {final['name']!r}"
    assert final["type"] == "AGENT", f"expected type AGENT, got {final['type']!r}"
    assert final["description"] == "behavioral check assistant", (
        f"expected description 'behavioral check assistant', got {final['description']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
