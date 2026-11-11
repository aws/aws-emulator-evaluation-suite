"""list-attach-points-matches-created-connection-attach-point."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-attach-points-matches-created-connection-attach-point"
GROUP = "data-plane"
SERVICES = ["interconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AttachPoint used to create a Connection is echoed back and appears in ListAttachPoints for
    that Environment, tagged with the same descriptor type CreateConnection's union variant implies."""
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

    assert conn["attachPoint"] == attach_point, conn

    listed = ic.list_attach_points(environmentId=env["environmentId"]).get("attachPoints", [])
    used_key, used_identifier = next(iter(attach_point.items()))
    matches = [ap for ap in listed if ap["identifier"] == used_identifier]
    assert matches, (used_identifier, [ap["identifier"] for ap in listed])

    expected_type = "DirectConnectGateway" if used_key == "directConnectGateway" else "ARN"
    assert matches[0]["type"] == expected_type, matches[0]


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
    """The service requires remoteAccount.identifier whenever the Environment declares a remote
    identifier type."""
    if env.get("remoteIdentifierType"):
        return {"remoteAccount": {"identifier": "sim2real-behav-remote-account"}}
    return {}


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


def _safe_delete_gateway(dc, gateway_id):
    from botocore.exceptions import ClientError

    try:
        dc.delete_direct_connect_gateway(directConnectGatewayId=gateway_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


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
