"""cfn-redshift-cluster-kms-key-id-round-trip-and-endpoint-getatt."""

from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-cluster-kms-key-id-round-trip-and-endpoint-getatt"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "redshift"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
    }
)
_POLL_S = 2.0
_DELETE_BUDGET_S = 900.0
#: One cheap current-generation node type that runs as a single node; asserted orderable first.
_NODE_TYPE = "ra3.large"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(ctx, cf, stack_id, terminal=_TERMINAL, timeout_s=900.0):
    """Poll DescribeStacks by StackId until a status in ``terminal``; return it."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} still {status!r}: the run budget ended first; not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(_POLL_S)


def stack_events(cf, stack_id):
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events[::-1]


def failure_reasons(cf, stack_id):
    return [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in stack_events(cf, stack_id)
        if e["ResourceStatus"].endswith("FAILED")
    ]


def stack_outputs(cf, stack_id):
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def delete_stack(ctx, cf, stack_id):
    """Delete by StackId whatever its state; raise unless it ends DELETE_COMPLETE."""
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        wait_stack(ctx, cf, stack_id, _TERMINAL, _DELETE_BUDGET_S)
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(ctx, cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _DELETE_BUDGET_S)
    if status != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} delete ended {status!r}: {failure_reasons(cf, stack_id)!r}"
        )


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _password() -> str:
    alphabet = string.ascii_letters + string.digits
    body = "".join(secrets.choice(alphabet) for _ in range(20))
    return "Aa1" + body


def _assert_orderable(rs) -> None:
    """``_NODE_TYPE`` is orderable as a single-node cluster here, read across every page."""
    pages = rs.get_paginator("describe_orderable_cluster_options").paginate(NodeType=_NODE_TYPE)
    types = {o["ClusterType"] for page in pages for o in page["OrderableClusterOptions"]}
    assert "single-node" in types, f"{_NODE_TYPE} is not orderable single-node here: {types!r}"


_KEY_DESCRIPTION = "sim2real behavioral redshift cluster key"
_ADMIN_USER = "s2rcfnadmin"


def _template() -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ClusterIdentifierParam": {"Type": "String"},
                "AdminUserPasswordParam": {"Type": "String", "NoEcho": True},
            },
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": _KEY_DESCRIPTION,
                        "PendingWindowInDays": 7,
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowAccountFullAccess",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": {
                                            "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
                                        }
                                    },
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                },
                "Cluster": {
                    "Type": "AWS::Redshift::Cluster",
                    "DeletionPolicy": "Delete",
                    "UpdateReplacePolicy": "Delete",
                    "Properties": {
                        "ClusterIdentifier": {"Ref": "ClusterIdentifierParam"},
                        "ClusterType": "single-node",
                        "NodeType": _NODE_TYPE,
                        "MasterUsername": _ADMIN_USER,
                        "MasterUserPassword": {"Ref": "AdminUserPasswordParam"},
                        "DBName": "dev",
                        "PubliclyAccessible": False,
                        "Encrypted": True,
                        "KmsKeyId": {"Ref": "Key"},
                        "Tags": [{"Key": "sim2real", "Value": "behavioral-check"}],
                    },
                },
            },
            "Outputs": {
                "ClusterIdentifierOut": {"Value": {"Ref": "Cluster"}},
                "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}},
                "EndpointAddress": {"Value": {"Fn::GetAtt": ["Cluster", "Endpoint.Address"]}},
                "EndpointPort": {"Value": {"Fn::GetAtt": ["Cluster", "Endpoint.Port"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::Redshift::Cluster's KmsKeyId reads back as the stack's own key's ARN,
    GetAtt Endpoint.Address/Port match DescribeClusters on port 5439, and deleting the stack
    removes the cluster, leaves no manual snapshot and schedules the key's deletion.
    """
    cfn = ctx.client("cloudformation")
    rs = ctx.client("redshift")
    kms = ctx.client("kms")

    _assert_orderable(rs)
    cluster_id = ctx.unique_name("sim2real-cfnrs-kmskey-").lower()
    stack_name = ctx.unique_name("sim2real-cfnrs-kmskey-stack-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "ClusterIdentifierParam", "ParameterValue": cluster_id},
            {"ParameterKey": "AdminUserPasswordParam", "ParameterValue": _password()},
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )["StackId"]
    ctx.on_cleanup(lambda: delete_stack(ctx, cfn, stack_id))

    status = wait_stack(ctx, cfn, stack_id, timeout_s=900)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack_id} ended {status!r}: {failure_reasons(cfn, stack_id)!r}"
    )

    out = stack_outputs(cfn, stack_id)
    cluster = rs.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][0]
    got = (
        cluster["NodeType"],
        cluster["MasterUsername"],
        cluster["Encrypted"],
        cluster["KmsKeyId"],
    )
    want = (_NODE_TYPE, _ADMIN_USER, True, out["KeyArn"])
    assert got == want, f"DescribeClusters read {got!r}, expected {want!r}"
    key = kms.describe_key(KeyId=out["KeyArn"])["KeyMetadata"]
    got = (key["KeyState"], key["Description"])
    assert got == ("Enabled", _KEY_DESCRIPTION), f"the cluster's key reads {got!r}"

    endpoint = cluster["Endpoint"]
    assert endpoint["Port"] == 5439, f"expected the cluster on port 5439, got {endpoint!r}"
    assert (out["EndpointAddress"], out["EndpointPort"]) == (endpoint["Address"], "5439"), (
        f"GetAtt Endpoint {out['EndpointAddress']!r}:{out['EndpointPort']!r} != "
        f"DescribeClusters {endpoint!r}"
    )

    delete_stack(ctx, cfn, stack_id)
    got = _error(lambda: rs.describe_clusters(ClusterIdentifier=cluster_id))
    want = ("ClusterNotFound", f"Cluster {cluster_id} not found.")
    assert got == want, f"DescribeClusters after the delete: {got!r}, expected {want!r}"
    snapshots = rs.describe_cluster_snapshots(ClusterIdentifier=cluster_id, SnapshotType="manual")
    assert snapshots["Snapshots"] == [], f"the delete left snapshots {snapshots['Snapshots']!r}"
    key = kms.describe_key(KeyId=out["KeyArn"])["KeyMetadata"]
    got = (key["KeyState"], key.get("PendingDeletionWindowInDays"))
    # DescribeKey reports PendingDeletionWindowInDays only for a pending replica deletion.
    assert got == ("PendingDeletion", None), f"the stack's key after the delete reads {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
