"""update-connection-nonexistent-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-connection-nonexistent-id-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateConnection on a real connection persists its description, while on a nonexistent id it fails
    with ResourceNotFoundException and its exact message, and GetConnection on that id is refused too."""
    ic = ctx.client("interconnect")
    env, attach_point, bandwidth = _provision_prereqs(ctx, ic)

    conn = ic.create_connection(
        bandwidth=bandwidth,
        attachPoint=attach_point,
        environmentId=env["environmentId"],
        description="sim2real behav control description",
        tags={"sim2real-purpose": "update-connection-nonexistent-id-control"},
        remoteAccount={"identifier": "sim2real-behav-remote-account"},
    )["connection"]
    connection_id = conn["id"]
    ctx.on_cleanup(lambda: _safe_delete(ic, connection_id))

    control_description = "sim2real behav control updated description"
    updated = ic.update_connection(identifier=connection_id, description=control_description)["connection"]
    assert updated["description"] == control_description, updated

    missing_id = "mcc-ffffffff"
    code, message = _error(lambda: ic.update_connection(identifier=missing_id, description="does not matter"))
    assert code == "ResourceNotFoundException", code
    assert message == f"Unable to process request: Connection does not exist for {missing_id}", message

    fetched = ic.get_connection(identifier=connection_id)["connection"]
    assert fetched["description"] == control_description, fetched

    get_nonexistent_code, get_nonexistent_message = _error(lambda: ic.get_connection(identifier=missing_id))
    assert get_nonexistent_code == "ResourceNotFoundException", get_nonexistent_code
    assert get_nonexistent_message == (
        f"Unable to process request: Unable to retrieve connection {missing_id}, as it does not exist"
    ), get_nonexistent_message


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


def _adopt_or_create_attach_point(ctx, ic, environment_id):
    """Attach points are account-owned (a Direct Connect Gateway) rather than something the
    Environment's partner provisions, so adopt one if it exists and create-or-adopt one
    otherwise instead of failing on a fresh account that has none yet."""
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

    def probe():
        return _first_attach_point(ic, environment_id)

    adopted = _poll_until(probe, lambda ap: ap is not None, timeout_s=60, interval_s=3)
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
    import time

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
    import time

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
