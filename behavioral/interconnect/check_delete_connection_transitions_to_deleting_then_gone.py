"""delete-connection-transitions-to-deleting-then-gone."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-connection-transitions-to-deleting-then-gone"
GROUP = "state"
SERVICES = ["interconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteConnection is accepted, and the Connection reaches its terminal deleted state (or is gone)."""
    ic = ctx.client("interconnect")
    env, attach_point, bandwidth = _provision_prereqs(ctx, ic)
    conn = ic.create_connection(
        bandwidth=bandwidth,
        attachPoint=attach_point,
        environmentId=env["environmentId"],
        **_remote_account_param(env),
    )["connection"]
    connection_id = conn["id"]
    ctx.on_cleanup(lambda: _safe_delete(ic, connection_id))

    delete_resp = ic.delete_connection(identifier=connection_id)["connection"]
    assert delete_resp["id"] == connection_id, delete_resp

    final_state = _wait_deleted(ic, connection_id)
    assert final_state in ("gone", "deleted"), final_state


def _usable_environment(ic):
    envs = ic.list_environments().get("environments", [])
    for env in envs:
        if env.get("state") == "unavailable":
            continue
        if env.get("bandwidths", {}).get("available"):
            return env
    return None


def _remote_account_param(env):
    """An Environment that declares remoteIdentifierType requires remoteAccount on CreateConnection."""
    if env.get("remoteIdentifierType"):
        return {"remoteAccount": {"identifier": "sim2real-behav-remote-account"}}
    return {}


def _listed_attach_point(ic, environment_id, gateway_id):
    listed = ic.list_attach_points(environmentId=environment_id).get("attachPoints", [])
    for ap in listed:
        if ap.get("identifier") == gateway_id:
            return ap
    return None


def _create_attach_point(ctx, ic, environment_id):
    """The attach point is a Direct Connect Gateway this check creates and deletes itself."""
    dc = ctx.client("directconnect")
    gateway = dc.create_direct_connect_gateway(
        directConnectGatewayName=ctx.unique_name("sim2real-behav-icdxgw-"),
        amazonSideAsn=64512,
    )["directConnectGateway"]
    gateway_id = gateway["directConnectGatewayId"]
    ctx.on_cleanup(lambda: _safe_delete_gateway(dc, gateway_id))
    _poll_until(
        lambda: _listed_attach_point(ic, environment_id, gateway_id),
        lambda ap: ap is not None,
        timeout_s=60,
        interval_s=3,
    )
    return {"directConnectGateway": gateway_id}


def _provision_prereqs(ctx, ic):
    env = _usable_environment(ic)
    if env is None:
        raise AssertionError(
            "no accessible Interconnect Environment with state != 'unavailable' and an available "
            "bandwidth was found in this account/region; a real Connection can only be created "
            "against a pre-provisioned partner Environment, which cannot be created via this API"
        )
    attach_point = _create_attach_point(ctx, ic, env["environmentId"])
    bandwidth = env["bandwidths"]["available"][0]
    return env, attach_point, bandwidth


def _connection_state(ic, connection_id):
    from botocore.exceptions import ClientError

    try:
        return ic.get_connection(identifier=connection_id)["connection"]["state"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return "gone"
        raise


def _wait_deleted(ic, connection_id):
    return _poll_until(
        lambda: _connection_state(ic, connection_id),
        lambda s: s in ("gone", "deleted"),
        timeout_s=150,
        interval_s=3,
    )


def _safe_delete(ic, connection_id):
    """Delete the Connection and wait until it is deleted, so its gateway can be deleted after it."""
    from botocore.exceptions import ClientError

    if _connection_state(ic, connection_id) in ("gone", "deleted"):
        return
    try:
        ic.delete_connection(identifier=connection_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _wait_deleted(ic, connection_id)


def _safe_delete_gateway(dc, gateway_id):
    from botocore.exceptions import ClientError

    try:
        dc.delete_direct_connect_gateway(directConnectGatewayId=gateway_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
