"""get-cluster-credentials-with-iam-federated-access."""
from __future__ import annotations

import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

from behavioral_harness import tags

CHECK = "get-cluster-credentials-with-iam-federated-access"
GROUP = "data-plane"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetClusterCredentialsWithIAM derives a stable "IAM:<name>" DbUser from the caller's ARN,
    never the "IAMA:" auto-create form, and mints a fresh password per call."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    cluster = _create_available_cluster(ctx)
    duration_seconds = 900

    caller_arn = sts.get_caller_identity()["Arn"]

    iam_creds_1 = redshift.get_cluster_credentials_with_iam(
        ClusterIdentifier=cluster["id"], DbName="dev", DurationSeconds=duration_seconds
    )
    iam_creds_2 = redshift.get_cluster_credentials_with_iam(
        ClusterIdentifier=cluster["id"], DbName="dev", DurationSeconds=duration_seconds
    )
    explicit_creds = redshift.get_cluster_credentials(
        ClusterIdentifier=cluster["id"],
        DbUser="iamformatcheck",
        DbName="dev",
        AutoCreate=True,
        DurationSeconds=duration_seconds,
    )

    # DbUser is non-empty and identity-derived: the SAME caller identity maps deterministically
    # to the SAME database user across independent calls (1:1 mapping), unlike a random token.
    assert iam_creds_1["DbUser"], "expected a non-empty DbUser from GetClusterCredentialsWithIAM"
    assert iam_creds_1["DbUser"] == iam_creds_2["DbUser"], (
        "the SAME caller identity must map to the SAME DbUser across independent calls, got "
        f"{iam_creds_1['DbUser']!r} then {iam_creds_2['DbUser']!r}"
    )

    # This API has no AutoCreate parameter, so it can never mint the auto-create "IAMA:" identity
    # -- only the plain "IAM:" identity, whose name is derived from the caller's own ARN rather
    # than supplied by the caller (unlike the explicit-DbUser flow below).
    assert iam_creds_1["DbUser"].startswith("IAM:"), (
        f"GetClusterCredentialsWithIAM must return the plain 'IAM:' identity prefix, got "
        f"{iam_creds_1['DbUser']!r}"
    )
    derived_name = iam_creds_1["DbUser"][len("IAM:") :]
    assert derived_name and derived_name in caller_arn, (
        f"the identity-derived name {derived_name!r} must be derived from the caller's own ARN, "
        f"got DbUser={iam_creds_1['DbUser']!r} for caller ARN {caller_arn!r}"
    )
    assert not iam_creds_1["DbUser"].startswith("IAMA:"), (
        f"GetClusterCredentialsWithIAM has no AutoCreate parameter and must never mint the "
        f"auto-create 'IAMA:' identity, got {iam_creds_1['DbUser']!r}"
    )
    assert explicit_creds["DbUser"] == "IAMA:iamformatcheck", (
        "GetClusterCredentials(AutoCreate=True, DbUser='iamformatcheck') must mint the auto-create "
        f"identity 'IAMA:iamformatcheck', got {explicit_creds['DbUser']!r}"
    )

    assert iam_creds_1["DbPassword"] and iam_creds_2["DbPassword"], (
        "expected a non-empty DbPassword on both GetClusterCredentialsWithIAM calls"
    )
    assert iam_creds_1["DbPassword"] != iam_creds_2["DbPassword"], (
        "each GetClusterCredentialsWithIAM call must mint a FRESH secret -- an emulator returning a "
        f"constant password fails this, got the same password {iam_creds_1['DbPassword']!r} twice"
    )


def _password() -> str:
    return "Sim2Real9" + secrets.token_hex(8)


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _orderable_node_type(redshift, cluster_type: str = "single-node") -> str:
    """A node type this account can order: availability varies by account/region (dc2 vs ra3), so a
    hardcoded literal can be rejected with InvalidParameterValue."""
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
            raise AssertionError(f"no orderable {cluster_type!r} node types in this account/region")
        chosen = sorted(available)[0]
    return chosen


def _create_available_cluster(ctx) -> dict[str, Any]:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-rs-")
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_orderable_node_type(redshift),
        ClusterType="single-node",
        MasterUsername="adminuser",
        MasterUserPassword=_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True)
    )

    deadline = time.monotonic() + 900.0
    status = None
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        status = clusters[0]["ClusterStatus"]
        if status == "available":
            break
        time.sleep(2)
    if status != "available":
        raise AssertionError(f"cluster {cluster_id} never reached 'available' (last status={status})")

    return {"id": cluster_id}


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
