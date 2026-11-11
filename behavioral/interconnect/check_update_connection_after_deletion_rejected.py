"""update-connection-after-deletion-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-connection-after-deletion-rejected"
GROUP = "overly-permissive"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConnection on a fully deleted Connection is rejected, does not resurrect it, and a live Connection still updates fine.

    A deleted Connection stays readable in the terminal 'deleted' state, so the rejection is a
    state refusal (InterconnectClientException) rather than a not-found."""
    ic = ctx.client("interconnect")
    env, attach_point, bandwidth = _provision_prereqs(ctx, ic)

    conn = ic.create_connection(
        bandwidth=bandwidth,
        attachPoint=attach_point,
        environmentId=env["environmentId"],
        tags={"sim2real": "behavioral"},
        **_remote_account_param(env),
    )["connection"]
    connection_id = conn["id"]
    ctx.on_cleanup(lambda: _safe_delete(ic, connection_id))
    ic.delete_connection(identifier=connection_id)

    def probe():
        return ic.get_connection(identifier=connection_id)["connection"]["state"]

    _poll_until(probe, lambda s: s == "deleted", timeout_s=150, interval_s=3)

    code, message = _error(
        lambda: ic.update_connection(identifier=connection_id, description="post-delete-update")
    )
    assert code == "InterconnectClientException", (
        f"expected UpdateConnection on a deleted Connection to be rejected with "
        f"InterconnectClientException, got {code!r}"
    )
    assert message == (
        f"Unable to process request: Cannot update connection {connection_id}: "
        "only connections in 'requested' or 'available' state can be updated"
    ), f"got {message!r}"

    # effect absent: the deleted connection did not come back and was not partially updated
    after = ic.get_connection(identifier=connection_id)["connection"]
    assert after["state"] == "deleted", (
        f"expected the deleted Connection to stay deleted after the rejected UpdateConnection, got {after['state']!r}"
    )
    assert after.get("description") != "post-delete-update", (
        f"expected the rejected UpdateConnection to leave the description unchanged, got {after.get('description')!r}"
    )

    # positive control: UpdateConnection succeeds against a freshly created, still-existing connection
    conn2 = ic.create_connection(
        bandwidth=bandwidth,
        attachPoint=attach_point,
        environmentId=env["environmentId"],
        tags={"sim2real": "behavioral"},
        **_remote_account_param(env),
    )["connection"]
    ctx.on_cleanup(lambda: _safe_delete(ic, conn2["id"]))
    updated = ic.update_connection(identifier=conn2["id"], description="sim2real behav control update")[
        "connection"
    ]
    assert updated["description"] == "sim2real behav control update", (
        f"expected UpdateConnection on a live Connection to persist the new description, "
        f"got {updated['description']!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _usable_environment(ic):
    envs = ic.list_environments().get("environments", [])
    for env in envs:
        if env.get("state") == "unavailable":
            continue
        if env.get("bandwidths", {}).get("available"):
            return env
    return None


def _attach_point_param(attach_point_descriptor):
    if attach_point_descriptor.get("type") == "DirectConnectGateway":
        return {"directConnectGateway": attach_point_descriptor["identifier"]}
    return {"arn": attach_point_descriptor["identifier"]}


def _first_attach_point(ic, environment_id):
    resp = ic.list_attach_points(environmentId=environment_id)
    attach_points = resp.get("attachPoints", [])
    return attach_points[0] if attach_points else None


def _remote_account_param(env):
    """The service requires remoteAccount.identifier whenever the Environment declares a remote identifier type."""
    if env.get("remoteIdentifierType"):
        return {"remoteAccount": {"identifier": "sim2real-behav-remote-account"}}
    return {}


def _adopt_or_create_attach_point(ctx, ic, environment_id):
    """Attach points are account-owned Direct Connect Gateways: adopt one, or create one and wait for it to list."""
    existing = _first_attach_point(ic, environment_id)
    if existing is not None:
        return _attach_point_param(existing)

    dc = ctx.client("directconnect")
    gateway = dc.create_direct_connect_gateway(
        directConnectGatewayName=ctx.unique_name("sim2real-behav-icdxgw-"),
        amazonSideAsn=64512,
    )["directConnectGateway"]
    gateway_id = gateway["directConnectGatewayId"]
    ctx.on_cleanup(lambda: _safe_delete_gateway(dc, gateway_id))

    adopted = _poll_until(
        lambda: _first_attach_point(ic, environment_id), lambda ap: ap is not None, timeout_s=60, interval_s=3
    )
    return _attach_point_param(adopted)


def _provision_prereqs(ctx, ic):
    env = _usable_environment(ic)
    if env is None:
        raise AssertionError(
            "no accessible Interconnect Environment with state != 'unavailable' and an available "
            "bandwidth was found in this account/region; a real Connection can only be created "
            "against a pre-provisioned partner Environment, which cannot be created via this API"
        )
    attach_point = _adopt_or_create_attach_point(ctx, ic, env["environmentId"])
    bandwidth = env["bandwidths"]["available"][0]
    return env, attach_point, bandwidth


def _safe_delete(ic, connection_id):
    from botocore.exceptions import ClientError

    try:
        ic.delete_connection(identifier=connection_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_gateway(dc, gateway_id, timeout_s=600.0, interval_s=10.0):
    """Delete the gateway once the Connection's asynchronous teardown has detached its virtual interface."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            dc.delete_direct_connect_gateway(directConnectGatewayId=gateway_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            still_attached = "attached Virtual Interface" in err.response["Error"].get("Message", "")
            if not still_attached or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


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
