"""run-group-update-persists-max-cpus."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "run-group-update-persists-max-cpus"
GROUP = "state"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRunGroup changes maxCpus and the new value is durably reflected by GetRunGroup."""
    omics = ctx.client("omics")

    created = omics.create_run_group(
        requestId=ctx.unique_name("sim2real-rgreq-"),
        name=ctx.unique_name("sim2real-rungroup-"),
        maxCpus=5,
    )
    group_id = created["id"]
    ctx.on_cleanup(lambda: omics.delete_run_group(id=group_id))

    before = omics.get_run_group(id=group_id)
    assert before["maxCpus"] == 5, f"expected maxCpus 5 right after create, got {before['maxCpus']!r}"

    omics.update_run_group(id=group_id, maxCpus=42)

    after = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        after = omics.get_run_group(id=group_id)
        if after["maxCpus"] == 42:
            break
        time.sleep(2)

    assert after is not None and after["maxCpus"] == 42, (
        f"UpdateRunGroup did not persist: maxCpus is {after.get('maxCpus') if after else None!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
