"""create-datastore-client-token-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-datastore-client-token-idempotent"
GROUP = "idempotency"
SERVICES = ["medical-imaging"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDatastore called twice with the same clientToken and same parameters returns the
    same datastoreId instead of creating a second datastore."""
    mi = ctx.client("medical-imaging")
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")

    first = mi.create_datastore(datastoreName=name, clientToken=token, tags={"sim2real": "true"})
    datastore_id = first["datastoreId"]
    ctx.on_cleanup(lambda: mi.delete_datastore(datastoreId=datastore_id))
    second = mi.create_datastore(datastoreName=name, clientToken=token, tags={"sim2real": "true"})

    assert first["datastoreId"] == second["datastoreId"], (
        f"repeated CreateDatastore with the same clientToken returned a different datastoreId: "
        f"{first['datastoreId']!r} != {second['datastoreId']!r}"
    )

    listing = mi.list_datastores(maxResults=50)["datastoreSummaries"]
    matching = [d for d in listing if d["datastoreId"] == datastore_id]
    assert len(matching) == 1, "idempotent create should not create a duplicate datastore"

    # Drain to ACTIVE so cleanup's DeleteDatastore does not race a still-CREATING datastore.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            break
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
