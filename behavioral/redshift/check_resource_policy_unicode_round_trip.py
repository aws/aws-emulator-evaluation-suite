"""resource-policy-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource policy with unicode and nested Conditions round-trips with no unicode loss, but
    re-serialized: single-element Principal/Action/Resource arrays become bare strings, while
    multi-element arrays and the always-array Statement survive unchanged.
    """
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    cluster_id = ctx.unique_name("sim2real-rspol-").lower()
    subnet_group = _network_redshift_subnet_group(ctx, redshift)
    redshift.create_cluster(
        ClusterIdentifier=cluster_id,
        ClusterType="single-node",
        NodeType="ra3.xlplus",
        MasterUsername="policyadmin",
        MasterUserPassword=_master_password(),
        DBName="dev",
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        ClusterSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        )
    )

    status = _poll_cluster_status(redshift, cluster_id, timeout_s=900)
    assert status == "available", f"cluster never became available (status={status})"

    namespace_arn = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"][
        0
    ]["ClusterNamespaceArn"]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSelfAccountDescribeShares",
                "Effect": "Allow",
                "Principal": {"AWS": [f"arn:aws:iam::{account_id}:root"]},
                "Action": [
                    "redshift:DescribeDataSharesForProducer",
                    "redshift:AuthorizeDataShare",
                ],
                "Resource": [namespace_arn],
                "Condition": {
                    "StringEquals": {
                        "aws:ResourceTag/\u540d\u524d": "\u30c6\u30b9\u30c8-\U0001f38e-namespace"
                    },
                    "StringLike": {
                        "aws:ResourceTag/note": "*\u00fcn\u00efc\u00f6d\u00e9-\u043d\u0430\u0433\u0440\u0443\u0437\u043a\u0430*"
                    },
                },
            }
        ],
    }
    policy_str = json.dumps(policy, ensure_ascii=False)

    redshift.put_resource_policy(ResourceArn=namespace_arn, Policy=policy_str)
    ctx.on_cleanup(lambda: redshift.delete_resource_policy(ResourceArn=namespace_arn))

    fetched = redshift.get_resource_policy(ResourceArn=namespace_arn)["ResourcePolicy"]
    assert fetched["ResourceArn"] == namespace_arn, (
        f"expected ResourceArn={namespace_arn!r}, got {fetched['ResourceArn']!r}"
    )
    fetched_doc = json.loads(fetched["Policy"])
    expected_doc = _canonicalize_singleton_arrays(policy)
    assert fetched_doc == expected_doc, (
        "resource policy was not preserved under the service's own canonicalization "
        "(single-element Principal/Action/Resource array -> scalar string): "
        f"expected={expected_doc!r} actual={fetched_doc!r}"
    )

    stmt = fetched_doc["Statement"][0]
    condition = stmt["Condition"]
    assert condition["StringEquals"]["aws:ResourceTag/名前"] == (
        "テスト-\U0001f38e-namespace"
    ), f"unicode condition value mangled: {condition['StringEquals']!r}"
    assert condition["StringLike"]["aws:ResourceTag/note"] == (
        "*ünïcödé-нагрузка*"
    ), f"unicode condition value mangled: {condition['StringLike']!r}"
    assert "名前" in fetched["Policy"] and "\U0001f38e" in fetched["Policy"], (
        "unicode substring not found verbatim in the raw stored policy string "
        f"(possible re-encoding): stored={fetched['Policy']!r}"
    )


_SINGLETON_COLLAPSIBLE_KEYS = {"Action", "NotAction", "Resource", "NotResource", "AWS"}


def _canonicalize_singleton_arrays(node):
    """Mirror the service's own normalization: a one-element array under a
    Principal/Action/Resource-shaped key becomes a bare scalar; everything else
    (notably the always-array ``Statement``) is left alone."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            value = _canonicalize_singleton_arrays(value)
            if key in _SINGLETON_COLLAPSIBLE_KEYS and isinstance(value, list) and len(value) == 1:
                value = value[0]
            out[key] = value
        return out
    if isinstance(node, list):
        return [_canonicalize_singleton_arrays(item) for item in node]
    return node


def _master_password() -> str:
    import secrets

    return f"PolAdm1n{secrets.token_hex(4)}"


def _poll_cluster_status(redshift, cluster_id: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "unknown"
    while time.monotonic() < deadline:
        clusters = redshift.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        status = clusters[0]["ClusterStatus"]
        if status == "available":
            return status
        time.sleep(2)
    return status


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
