"""modify-lakehouse-configuration-dependent-service-errors."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-lakehouse-configuration-dependent-service-errors"
GROUP = "error-semantics"
SERVICES = ["redshift"]

MSG_LAKEHOUSE_NOT_FOUND = "The specified cluster identifier can't be found."
MSG_DESCRIBE_NOT_FOUND = "Cluster {cluster_id} not found."
MSG_NO_IDC = (
    "The RedshiftIdcApplication with the ARN {arn} wasn't found, or the status isn't Completed."
)
MSG_DRY_RUN = "Request would have succeeded, but DryRun flag is set."

# ra3.xlplus first: on ra3.large ModifyLakehouseConfiguration answers InvalidClusterState, so
# ra3.xlplus is the smallest node type that supports lakehouse registration. dc2 is a last-resort
# fallback where no RA3 type is orderable; it lacks lakehouse support entirely.
# large-instance: fallback when ra3.xlplus is not orderable; ra3.large and dc2 lack lakehouse support
_NODE_TYPE_PREFERENCE = ("ra3.xlplus", "ra3.4xlarge", "ra3.large", "dc2.large", "dc2.8xlarge")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyLakehouseConfiguration answers ClusterNotFound for a nonexistent cluster and
    RedshiftIdcApplicationNotExists for a registered cluster naming a nonexistent IdC application,
    each with its exact message, and a dry run on that cluster answers DryRunOperation."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # 1. Nonexistent cluster -> ClusterNotFound (no real cluster required). Redshift's
    #    query-protocol wire code drops the Smithy shape's "Fault" suffix.
    missing_cluster_id = ctx.unique_name("sim2real-behav-lhmiss-")
    code, message = _refusal(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=missing_cluster_id, LakehouseRegistration="Register"
        )
    )
    assert code == "ClusterNotFound", f"expected ClusterNotFound, got {code}"
    assert message == MSG_LAKEHOUSE_NOT_FOUND, (
        f"expected {MSG_LAKEHOUSE_NOT_FOUND!r}, got {message!r}"
    )

    # Effect absent: the call did not conjure a cluster into existence -- an independent read
    # for the same identifier still reports it missing.
    after_code, after_message = _refusal(
        lambda: redshift.describe_clusters(ClusterIdentifier=missing_cluster_id)
    )
    assert after_code == "ClusterNotFound", (
        f"expected {missing_cluster_id} to remain absent after the rejected call, "
        f"got {after_code}"
    )
    not_found = MSG_DESCRIBE_NOT_FOUND.format(cluster_id=missing_cluster_id)
    assert after_message == not_found, f"expected {not_found!r}, got {after_message!r}"

    cluster_id = ctx.unique_name("sim2real-behav-lh-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="s2radmin",
        MasterUserPassword="Sim2Real-Passw0rd1",
        PubliclyAccessible=False,
        Encrypted=True,
        AutomatedSnapshotRetentionPeriod=1,
        ClusterSubnetGroupName=subnet_group,
    )

    ctx.on_cleanup(lambda: _delete_cluster_retrying(redshift, cluster_id))
    _wait_cluster_available(redshift, cluster_id)
    # ClusterStatus can report "available" a short window before ClusterAvailabilityStatus
    # settles to "Available"; a mutating call issued in that window gets a spurious
    # InvalidClusterState that has nothing to do with the fault under test.
    _wait_cluster_availability(redshift, cluster_id, timeout_s=600.0)

    # LakehouseIdcRegistration="Associate" is only meaningful once the cluster itself is
    # lakehouse-registered; on an unregistered cluster it is rejected with
    # InvalidClusterState regardless of whether the referenced IdC application exists
    # (the precondition check runs before the ARN lookup).
    # Register first so the negative below isolates the IdC-application-not-found fault from
    # this unrelated precondition.
    _retry_on_invalid_cluster_state(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id, LakehouseRegistration="Register", CatalogName=cluster_id
        )
    )
    # Registration is asynchronous: it passes through REGISTRATION_REQUESTED before settling to
    # REGISTERED. Wait for the terminal status, not merely a non-null one, or the status can
    # still be moving in the background during the negative below for reasons that have nothing
    # to do with it.
    registered_status = _wait_until(
        lambda: redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
            "LakehouseRegistrationStatus"
        ),
        lambda status: status == "REGISTERED",
        timeout_s=180.0,
    )
    _wait_cluster_available(redshift, cluster_id)
    _wait_cluster_availability(redshift, cluster_id, timeout_s=600.0)

    # 2. Real, available, lakehouse-registered cluster referencing a nonexistent IDC application
    #    -> RedshiftIdcApplicationNotExists (same wire-code convention as above; a different
    #    dependency-resolution failure than ClusterNotFound, even though both read as
    #    "not found" style faults).
    bogus_idc_arn = (
        f"arn:aws:redshift:{ctx.region}:{account_id}:redshiftidcapplication:"
        "00000000-0000-0000-0000-000000000000"
    )
    code, message = _refusal_retrying(
        lambda: redshift.modify_lakehouse_configuration(
            ClusterIdentifier=cluster_id,
            LakehouseIdcApplicationArn=bogus_idc_arn,
            LakehouseIdcRegistration="Associate",
        )
    )
    assert code == "RedshiftIdcApplicationNotExists", f"expected RedshiftIdcApplicationNotExists, got {code}"
    expected = MSG_NO_IDC.format(arn=bogus_idc_arn)
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: the rejected association did not partially take. DescribeClusters exposes
    # only the aggregate LakehouseRegistrationStatus (the model carries no separate IdC-arn field
    # on the Cluster shape), so the independent read available here is that this status is
    # unchanged from the value observed right after Register -- the rejected call left no trace.
    after_status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
        "LakehouseRegistrationStatus"
    )
    assert after_status == registered_status, (
        f"expected LakehouseRegistrationStatus to remain {registered_status!r} after the "
        f"rejected IdC association, got {after_status!r}"
    )

    # Positive control: a dry-run against the same valid, available cluster (with no dangling
    # dependency reference) succeeds, proving the operation itself works for this cluster and
    # the two rejections above are precondition-specific. ModifyLakehouseConfiguration's DryRun
    # follows the EC2-style convention, not a normal 200: a would-succeed request is signalled by
    # *raising* ClientError(DryRunOperation) rather than returning a response.
    dry_run_code, dry_run_message = _refusal_retrying(
        lambda: redshift.modify_lakehouse_configuration(ClusterIdentifier=cluster_id, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", (
        f"expected the dry-run positive control to signal DryRunOperation "
        f"(request would have succeeded), got {dry_run_code!r}"
    )
    assert dry_run_message == MSG_DRY_RUN, f"expected {MSG_DRY_RUN!r}, got {dry_run_message!r}"


def _refusal(fn):
    """Call *fn*, which must be refused; return the AWS error ``(code, message)``.

    A call that succeeds raises ``AssertionError``: the refusal is the claim."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _delete_cluster_retrying(redshift, cluster_id: str, timeout_s: float = 840.0) -> None:
    """DeleteCluster, retried while the cluster is mid-modification. A cluster that still has
    a lakehouse Glue catalog refuses deletion (InvalidClusterState), so it is deregistered
    first; any other refusal raises so a leak is reported, not swallowed."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFound":
                return
            if code != "InvalidClusterState" or time.monotonic() >= deadline:
                raise
        cluster = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
        if (
            cluster.get("LakehouseRegistrationStatus") == "REGISTERED"
            and cluster["ClusterStatus"] == "available"
        ):
            try:
                redshift.modify_lakehouse_configuration(
                    ClusterIdentifier=cluster_id, LakehouseRegistration="Deregister"
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidClusterState":
                    raise
        time.sleep(15)


def _node_type(redshift, cluster_type: str = "single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this account/region.

    Node type availability (e.g. dc2 vs. ra3) varies by account -- many accounts reject dc2
    node types with InvalidParameterValue -- so it must be read from the account rather than
    pinned.
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


def _wait_cluster_available(redshift, cluster_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]["ClusterStatus"]
        if status == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not become available within {timeout_s}s")


def _wait_cluster_availability(
    redshift, cluster_id: str, timeout_s: float = 300.0, interval_s: float = 15.0
) -> None:
    deadline = time.monotonic() + timeout_s
    availability = None
    while time.monotonic() < deadline:
        availability = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0].get(
            "ClusterAvailabilityStatus"
        )
        if availability == "Available":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_id} availability never reached 'Available' within {timeout_s}s "
        f"(last={availability!r})"
    )


def _wait_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_invalid_cluster_state(fn, timeout_s: float = 180.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidClusterState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _refusal_retrying(fn, timeout_s: float = 180.0, interval_s: float = 15.0):
    """``_refusal``, retried while the cluster reports a transient InvalidClusterState."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _refusal(fn)
        if code != "InvalidClusterState" or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


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
