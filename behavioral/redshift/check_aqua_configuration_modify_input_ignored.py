"""aqua-configuration-modify-input-ignored."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aqua-configuration-modify-input-ignored"
GROUP = "overly-permissive"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyAquaConfiguration is retired: the requested AquaConfigurationStatus is ignored in the
    response and on a later read, and a nonexistent cluster is refused with InternalFailure and its
    exact message."""
    # Reference: https://docs.aws.amazon.com/redshift/latest/APIReference/API_ModifyAquaConfiguration.html
    redshift = ctx.client("redshift")

    # Negative on a nonexistent cluster: this retired operation does not surface the
    # documented ClusterNotFoundFault for an identifier that was never created; real AWS
    # fails it closed with a generic InternalFailure. It must never silently accept the call.
    bogus_cluster_id = ctx.unique_name("sim2real-aqua-ghost-")
    code, message = _error(
        lambda: redshift.modify_aqua_configuration(
            ClusterIdentifier=bogus_cluster_id, AquaConfigurationStatus="enabled"
        )
    )
    assert code == "InternalFailure", (
        f"expected InternalFailure for a nonexistent cluster, got {code!r}"
    )
    expected = "An internal error has occurred. Please try your query again at a later time."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    cluster_id = _create_available_cluster(ctx)

    # Ask for "enabled". ModifyAquaConfiguration is retired for every node type, not
    # just older ones, so the requested value must not be reported back.
    enabled_response = redshift.modify_aqua_configuration(
        ClusterIdentifier=cluster_id, AquaConfigurationStatus="enabled"
    )
    enabled_status = enabled_response["AquaConfiguration"]["AquaConfigurationStatus"]
    assert enabled_status != "enabled", (
        f"expected the retired AquaConfigurationStatus='enabled' input to be ignored, "
        f"but the response echoed back {enabled_status!r}"
    )

    # Ask for the opposite value next. The parameter is retired/ignored, so the
    # resulting status must be identical regardless of which value was requested.
    disabled_response = redshift.modify_aqua_configuration(
        ClusterIdentifier=cluster_id, AquaConfigurationStatus="disabled"
    )
    disabled_status = disabled_response["AquaConfiguration"]["AquaConfigurationStatus"]
    assert disabled_status == enabled_status, (
        f"expected the same auto-determined status regardless of requested input, but "
        f"AquaConfigurationStatus='enabled' -> {enabled_status!r} while "
        f"AquaConfigurationStatus='disabled' -> {disabled_status!r}"
    )

    # Resulting state: a fresh read (not just the mutate response) reflects the
    # same Redshift-determined status, not the last value we asked for.
    after = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0][
        "AquaConfiguration"
    ]["AquaConfigurationStatus"]
    assert after == disabled_status, (
        f"expected describe_clusters to reflect the same auto-determined status "
        f"{disabled_status!r} as the mutate response, got {after!r}"
    )


def _error(fn):
    """Call fn(); return (error code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this account/region.

    Which node types (if any) are orderable is an account-level entitlement --
    DC2 is withdrawn for new accounts in favor of RA3 -- so it must be discovered,
    never hardcoded.
    """
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = redshift.describe_orderable_cluster_options(**kwargs)
        for opt in resp.get("OrderableClusterOptions", []):
            if opt.get("ClusterType") != cluster_type:
                continue
            nt = opt.get("NodeType")
            if nt and nt not in available:
                available.append(nt)
        marker = resp.get("Marker")
        if not marker:
            break
    chosen = next((nt for nt in _NODE_TYPE_PREFERENCE if nt in available), None)
    if chosen is None:
        if not available:
            raise AssertionError(f"no orderable {cluster_type} options in this region")
        chosen = sorted(available)[0]
    return chosen


def _rand_password() -> str:
    return f"S2r{secrets.token_hex(4)}Aa1Xy"


def _create_available_cluster(ctx) -> str:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-aqua-cl-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername="sim2realadmin",
        MasterUserPassword=_rand_password(),
        ClusterType="single-node",
        PubliclyAccessible=False,
        Encrypted=True,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    return cluster_id


def _wait_for_cluster_status(ctx, cluster_id: str, targets: set, timeout_s: float) -> None:
    redshift = ctx.client("redshift")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if cluster["ClusterStatus"] in targets:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} never reached {targets} within {timeout_s}s")


def _delete_cluster(ctx, cluster_id: str) -> None:
    redshift = ctx.client("redshift")
    try:
        _wait_for_cluster_status(ctx, cluster_id, {"available"}, timeout_s=900)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
    try:
        redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFound":
            raise
        return
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            redshift.describe_clusters(ClusterIdentifier=cluster_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ClusterNotFound":
                return
            raise
        time.sleep(15)


def _network_redshift_subnet_group(ctx, client) -> str:
    """A Redshift cluster subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-rsg-")
    client.create_cluster_subnet_group(
        ClusterSubnetGroupName=name,
        Description="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_cluster_subnet_group(ClusterSubnetGroupName=name),
            ("InvalidClusterSubnetGroupStateFault", "ClusterSubnetGroupInUse"),
            ("ClusterSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
