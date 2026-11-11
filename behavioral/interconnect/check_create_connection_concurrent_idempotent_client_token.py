"""create-connection-concurrent-idempotent-client-token."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-connection-concurrent-idempotent-client-token"
GROUP = "concurrency"
SERVICES = ["interconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateConnection calls sharing one clientToken produce exactly one Connection."""
    ic = ctx.client("interconnect")
    env, attach_point, bandwidth = _provision_prereqs(ctx, ic)
    client_token = ctx.unique_name("sim2real-behav-tok-")
    description = ctx.unique_name("sim2real-behav-conn-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def create(_):
        return ic.create_connection(
            bandwidth=bandwidth,
            attachPoint=attach_point,
            environmentId=env["environmentId"],
            description=description,
            clientToken=client_token,
            remoteAccount={"identifier": account_id},
        )["connection"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(create, range(5)))

    ids = {r["id"] for r in results}
    assert len(ids) == 1, f"idempotent CreateConnection produced {len(ids)} distinct connections: {ids}"
    connection_id = ids.pop()
    ctx.on_cleanup(lambda: _safe_delete(ic, connection_id))

    listed = ic.list_connections(environmentId=env["environmentId"]).get("connections", [])
    matching = [c for c in listed if c["id"] == connection_id]
    assert len(matching) == 1, f"expected exactly one listed Connection {connection_id}, found {len(matching)}"


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


def _create_direct_connect_gateway_attach_point(ctx, ic, environment_id):
    """AttachPoints are the caller's own Direct Connect Gateways (ListAttachPoints echoes what
    exists in-account) — not a partner-provisioned object, so create one and poll for it to
    become visible, rather than treating an empty list as an unfixable external prerequisite."""
    dc = ctx.client("directconnect")
    gw_name = ctx.unique_name("sim2real-behav-dxgw-")
    gateway = dc.create_direct_connect_gateway(directConnectGatewayName=gw_name)[
        "directConnectGateway"
    ]
    gateway_id = gateway["directConnectGatewayId"]
    ctx.on_cleanup(lambda: dc.delete_direct_connect_gateway(directConnectGatewayId=gateway_id))

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        attach_points = ic.list_attach_points(environmentId=environment_id).get("attachPoints", [])
        for ap in attach_points:
            if ap.get("type") == "DirectConnectGateway" and ap.get("identifier") == gateway_id:
                return ap
        time.sleep(2)
    raise AssertionError(
        f"created DirectConnectGateway {gateway_id} but it never appeared in ListAttachPoints "
        f"for Environment {environment_id} within 60s"
    )


def _provision_prereqs(ctx, ic):

    env = _usable_environment(ic)
    if env is None:
        raise AssertionError(
            "no accessible Interconnect Environment with state != 'unavailable' and an available "
            "bandwidth was found in this account/region; a real Connection can only be created "
            "against a pre-provisioned partner Environment, which cannot be created via this API"
        )
    attach_point_descriptor = _first_attach_point(ic, env["environmentId"])
    if attach_point_descriptor is None:
        attach_point_descriptor = _create_direct_connect_gateway_attach_point(
            ctx, ic, env["environmentId"]
        )
    bandwidth = env["bandwidths"]["available"][0]
    return env, _attach_point_param(attach_point_descriptor), bandwidth


def _safe_delete(ic, connection_id):
    from botocore.exceptions import ClientError

    try:
        ic.delete_connection(identifier=connection_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
