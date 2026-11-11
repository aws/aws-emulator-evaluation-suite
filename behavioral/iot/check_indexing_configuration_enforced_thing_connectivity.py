"""indexing-configuration-enforced-thing-connectivity."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "indexing-configuration-enforced-thing-connectivity"
GROUP = "server-side"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-indexing")
def run(ctx) -> None:
    """GetThingConnectivityData is rejected with InvalidRequestException while connectivity
    indexing is OFF, and starts returning a live (never-connected) status once
    UpdateIndexingConfiguration turns thingConnectivityIndexingMode to STATUS."""
    iot = ctx.client("iot")

    original = iot.get_indexing_configuration().get("thingIndexingConfiguration", {})
    original_mode = original.get("thingIndexingMode", "OFF")
    original_connectivity_mode = original.get("thingConnectivityIndexingMode", "OFF")

    def _restore():
        iot.update_indexing_configuration(
            thingIndexingConfiguration={
                "thingIndexingMode": original_mode,
                "thingConnectivityIndexingMode": original_connectivity_mode,
            }
        )

    ctx.on_cleanup(_restore)

    thing_name = ctx.unique_name("sim2real-iot-connectivity-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    # Step 1: force connectivity indexing OFF and confirm the call is rejected.
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "thingConnectivityIndexingMode": "OFF",
        }
    )
    _poll_until(
        lambda: iot.get_indexing_configuration()["thingIndexingConfiguration"].get(
            "thingConnectivityIndexingMode"
        ),
        lambda mode: mode == "OFF",
        timeout_s=30.0,
    )
    # The mode flips before the index settles: while it rebuilds, the call is refused with
    # IndexNotReadyException instead, so grade the rejection only once the index is ACTIVE.
    _poll_until(
        lambda: iot.describe_index(indexName="AWS_Things")["indexStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=300.0,
        interval_s=5.0,
    )

    code, message = _error(lambda: iot.get_thing_connectivity_data(thingName=thing_name))
    assert code == "InvalidRequestException", (
        f"expected a rejection while connectivity indexing is disabled, got {code}"
    )
    assert message == (
        "connectivity indexing has not been enabled on AWS_Things index. Please update your indexing "
        "configuration and wait for the index to become active."
    ), message

    # Step 2: enable connectivity indexing and confirm GetThingConnectivityData now succeeds.
    iot.update_indexing_configuration(
        thingIndexingConfiguration={
            "thingIndexingMode": "REGISTRY",
            "thingConnectivityIndexingMode": "STATUS",
        }
    )
    _poll_until(
        lambda: iot.get_indexing_configuration()["thingIndexingConfiguration"].get(
            "thingConnectivityIndexingMode"
        ),
        lambda mode: mode == "STATUS",
        timeout_s=30.0,
    )

    def _get_connectivity():
        try:
            return ("ok", iot.get_thing_connectivity_data(thingName=thing_name), None)
        except ClientError as err:
            return (err.response["Error"]["Code"], None, err.response["Error"].get("Message", ""))

    # Connectivity indexing requires a full index rebuild, which can take several minutes on real
    # AWS; until it completes the call is refused (IndexNotReadyException, or the config-level
    # InvalidRequestException while the mode change propagates). Poll past only those refusals.
    result = _poll_until(
        _get_connectivity,
        lambda r: r[0] not in _REBUILD_REFUSALS,
        timeout_s=360.0,
        interval_s=15.0,
    )
    status, response, message = result
    assert status == "ok", (
        f"expected GetThingConnectivityData to answer once the index rebuilt, got {status}: {message}"
    )
    assert response["connected"] is False, f"a thing that never connected must report connected=False: {response!r}"


_REBUILD_REFUSALS = {"IndexNotReadyException", "InvalidRequestException"}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
