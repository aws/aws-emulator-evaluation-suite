"""put-resource-policy-invalid-json-rejected."""
from __future__ import annotations

import time

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-invalid-json-rejected"
GROUP = "data-plane"
SERVICES = ["redshift"]

_UNPARSEABLE_POLICY = "The resource policy can't be parsed."
_NO_POLICY = "The requested resource policy doesn\u2019t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a malformed policy document with InvalidPolicyFault, leaves no
    policy attached to the resource, while a well-formed policy on the same resource still succeeds."""
    redshift = ctx.client("redshift")
    cluster = _create_available_cluster(ctx)
    # PutResourcePolicy targets the cluster's *namespace* ARN, not its cluster ARN: a cluster
    # ARN is rejected outright with "Resource type cluster isn't supported for the resource
    # policy", so the namespace ARN from DescribeClusters is the resource under test.
    namespace_arn = cluster["namespace_arn"]

    malformed_policy = "{this is not valid json"
    code, message = _error(lambda: redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=malformed_policy))
    assert code == "InvalidPolicyFault", f"expected InvalidPolicyFault for malformed JSON, got {code!r}"
    assert message == _UNPARSEABLE_POLICY, f"unexpected InvalidPolicyFault message {message!r}"

    # Effect absent: nothing was stored for this resource.
    code_after, message_after = _error(lambda: redshift.get_resource_policy(ResourceArn=namespace_arn))
    assert code_after == "ResourceNotFoundFault", (
        f"malformed PutResourcePolicy must leave no policy attached, expected ResourceNotFoundFault, "
        f"got {code_after!r}"
    )
    assert message_after == _NO_POLICY, f"unexpected ResourceNotFoundFault message {message_after!r}"

    # Positive control: a well-formed policy on the very same resource is accepted.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ControlStatement",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift:CreateInboundIntegration",
                "Resource": namespace_arn,
            }
        ],
    }
    put_resp = redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=json.dumps(good_policy))
    ctx.on_cleanup(lambda: _delete_policy_quiet(redshift, namespace_arn))
    assert json.loads(put_resp["ResourcePolicy"]["Policy"]) == good_policy, (
        "PutResourcePolicy's own response should echo the well-formed policy just stored"
    )

    # Terminal read: independent of the mutating call, at the destination.
    stored = redshift.get_resource_policy(ResourceArn=namespace_arn)
    stored_policy = json.loads(stored["ResourcePolicy"]["Policy"])
    assert stored_policy == good_policy, (
        f"GetResourcePolicy should read back the well-formed policy, expected {good_policy}, got {stored_policy}"
    )


# large-instance: last-resort fallback; the first orderable type in this order is used, so smaller types win
_NODE_TYPE_PREFERENCE = ("dc2.large", "ra3.large", "ra3.xlplus", "dc2.8xlarge", "ra3.4xlarge")


def _node_type(rs, cluster_type="single-node") -> str:
    """Cheapest orderable node type for *cluster_type* in this region/account."""
    available: list[str] = []
    marker = None
    while True:
        kwargs = {"MaxRecords": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = rs.describe_orderable_cluster_options(**kwargs)
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


def _create_available_cluster(ctx) -> dict:
    redshift = ctx.client("redshift")
    cluster_id = ctx.unique_name("sim2real-rs-").lower()
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        NodeType=_node_type(redshift),
        MasterUsername="adminuser",
        MasterUserPassword="TestPassw0rd123",
        DBName="dev",
        ClusterType="single-node",
        PubliclyAccessible=False,
        # Encrypted at rest, as a customer would configure it.
        Encrypted=True,
        # RA3 node types refuse retention 0, so use the 1-day minimum.
        AutomatedSnapshotRetentionPeriod=1,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: redshift.delete_cluster(ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True))
    waiter = redshift.get_waiter("cluster_available")
    waiter.wait(ClusterIdentifier=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})
    described = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    return {"id": cluster_id, "namespace_arn": described["ClusterNamespaceArn"]}


def _delete_policy_quiet(redshift, arn: str) -> None:
    try:
        redshift.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundFault":
            raise


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
