"""update-application-modifies-maximum-capacity."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "update-application-modifies-maximum-capacity"
GROUP = "application-lifecycle"
SERVICES = ["emr-serverless"]


def _cpu_num(cpu_str):
    match = re.match(r"\s*([0-9]+)", cpu_str)
    assert match, f"unexpected cpu format: {cpu_str!r}"
    return int(match.group(1))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication on a CREATED application persists a new maximumCapacity, visible on the next GetApplication."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")

    app_id = emrs.create_application(
        name=name,
        releaseLabel="emr-7.9.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        maximumCapacity={"cpu": "2vCPU", "memory": "8GB"},
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))

    before = emrs.get_application(applicationId=app_id)["application"]
    assert _cpu_num(before["maximumCapacity"]["cpu"]) == 2, (
        f"expected initial maximumCapacity.cpu=2vCPU, got {before['maximumCapacity']['cpu']!r}"
    )
    assert before["maximumCapacity"]["memory"].strip().upper().startswith("8"), (
        f"expected initial maximumCapacity.memory to start with 8, got {before['maximumCapacity']['memory']!r}"
    )

    emrs.update_application(
        applicationId=app_id,
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        maximumCapacity={"cpu": "4vCPU", "memory": "16GB"},
    )

    after = emrs.get_application(applicationId=app_id)["application"]
    assert _cpu_num(after["maximumCapacity"]["cpu"]) == 4, (
        f"expected updated maximumCapacity.cpu=4vCPU, got {after['maximumCapacity']['cpu']!r}"
    )
    assert after["maximumCapacity"]["memory"].strip().upper().startswith("16"), (
        f"expected updated maximumCapacity.memory to start with 16, got {after['maximumCapacity']['memory']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

