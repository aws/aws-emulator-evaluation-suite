"""create-datastore-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-datastore-reaches-active"
GROUP = "state"
SERVICES = ["medical-imaging"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDatastore returns CREATING synchronously and the datastore transitions to ACTIVE."""
    mi = ctx.client("medical-imaging")
    name = ctx.unique_name("sim2real-mi-ds-")
    resp = mi.create_datastore(
        datastoreName=name,
        clientToken=ctx.unique_name("sim2real-mi-tok-"),
        tags={"sim2real": "behavioral"},
    )
    datastore_id = resp["datastoreId"]
    ctx.on_cleanup(lambda: mi.delete_datastore(datastoreId=datastore_id))

    # Real AWS always returns CREATING synchronously from CreateDatastore.
    assert resp["datastoreStatus"] == "CREATING"

    final_status = None
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        got = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
        final_status = got["datastoreStatus"]
        if final_status != "CREATING":
            break
        time.sleep(3)

    assert final_status == "ACTIVE", f"datastore did not reach ACTIVE, last status={final_status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
