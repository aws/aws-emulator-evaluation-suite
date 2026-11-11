"""shadow-version-conflict-stale-update."""
from __future__ import annotations

import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "shadow-version-conflict-stale-update"
GROUP = 'shadow'
SERVICES = ['iot']

def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _iot_data(ctx):
    """iot-data must hit the account-specific ATS data-plane endpoint on real AWS — the
    control-plane host answers shadow/retained-message ops with UnknownOperationException.
    Discover it via DescribeEndpoint(iot:Data-ATS) and route it through ctx.endpoint_url. (Transient connect blips are absorbed by the client's
    standard-retry mode.)"""
    ep = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(ep))


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateThingShadow with a stale version number must fail with a conflict, not overwrite —
    and the identical write at the CURRENT version must then succeed, proving the refusal was
    about the stale version and nothing else."""
    iot = ctx.client("iot")
    iot_data = _iot_data(ctx)
    thing = ctx.unique_name("sim2real-behav-thing-shadow-conflict-")
    iot.create_thing(thingName=thing)
    ctx.on_cleanup(lambda _n=thing: iot.delete_thing(thingName=_n))

    r1 = iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"x": 1}}})
    )
    doc1 = json.loads(r1["payload"].read())
    stale_version = doc1["version"]

    # advance the shadow so `stale_version` is no longer current
    r2 = iot_data.update_thing_shadow(
        thingName=thing, payload=json.dumps({"state": {"reported": {"x": 2}}})
    )
    current_version = json.loads(r2["payload"].read())["version"]

    code, code_message = _error(
        lambda: iot_data.update_thing_shadow(
            thingName=thing,
            payload=json.dumps({"state": {"reported": {"x": 3}}, "version": stale_version}),
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert code_message == "Version conflict", (
        f"expected the exact {code} message, got {code_message!r}"
    )

    # the stale write must not have applied
    got = iot_data.get_thing_shadow(thingName=thing)
    got_doc = json.loads(got["payload"].read())
    assert got_doc["state"]["reported"]["x"] == 2, got_doc["state"]["reported"]
    assert got_doc["version"] == current_version, (
        f"expected version to remain {current_version}, got {got_doc['version']}"
    )

    # RESTORE: the identical shape of write, now carrying the CURRENT version, must succeed.
    r3 = iot_data.update_thing_shadow(
        thingName=thing,
        payload=json.dumps({"state": {"reported": {"x": 3}}, "version": current_version}),
    )
    restored_version = json.loads(r3["payload"].read())["version"]
    assert restored_version == current_version + 1, (
        f"expected the restored write to land at version {current_version + 1}, "
        f"got {restored_version}"
    )

    # terminal read: independent of the mutation, at the destination
    final = iot_data.get_thing_shadow(thingName=thing)
    final_doc = json.loads(final["payload"].read())
    assert final_doc["state"]["reported"]["x"] == 3, final_doc["state"]["reported"]
    assert final_doc["version"] == restored_version, (
        f"expected version {restored_version}, got {final_doc['version']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
