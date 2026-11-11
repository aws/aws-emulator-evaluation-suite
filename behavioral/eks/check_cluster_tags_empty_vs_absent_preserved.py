"""cluster-tags-empty-vs-absent-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-tags-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Connected clusters registered without tags and with tags={} both show an empty tag map on
    DescribeCluster and ListTagsForResource.
    """
    eks = ctx.client("eks")
    cluster_no_tags, _ = _register_connected_cluster(ctx, tags_map=None)
    cluster_empty_tags, _ = _register_connected_cluster(ctx, tags_map={})

    name_no_tags = cluster_no_tags["name"]
    name_empty_tags = cluster_empty_tags["name"]

    desc_no_tags = eks.describe_cluster(name=name_no_tags)["cluster"]
    desc_empty_tags = eks.describe_cluster(name=name_empty_tags)["cluster"]

    assert desc_no_tags.get("tags", {}) == {}, (
        f"DescribeCluster for a cluster created with no tags param returned "
        f"tags={desc_no_tags.get('tags')!r}, expected an empty collection"
    )
    assert desc_empty_tags.get("tags", {}) == {}, (
        f"DescribeCluster for a cluster created with tags={{}} returned "
        f"tags={desc_empty_tags.get('tags')!r}, expected an empty collection"
    )

    list_no_tags = eks.list_tags_for_resource(resourceArn=desc_no_tags["arn"])["tags"]
    list_empty_tags = eks.list_tags_for_resource(resourceArn=desc_empty_tags["arn"])["tags"]

    assert list_no_tags == {}, (
        f"ListTagsForResource for the no-tags-param cluster returned {list_no_tags!r}, "
        f"expected an empty collection"
    )
    assert list_empty_tags == {}, (
        f"ListTagsForResource for the tags={{}} cluster returned {list_empty_tags!r}, "
        f"expected an empty collection"
    )


# A connected cluster is used because it is the
# cheapest resource in EKS that owns a real taggable ARN: no control plane, no EC2, no hourly
# charge.


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {desc}; last={val!r}"
            )
        time.sleep(interval_s)
        val = fn()
    return val


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get(
            "AttachedPolicies", []
        ):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_connector_role(ctx):
    """Create an IAM role the EKS connector service can assume; return its ARN."""
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-connector-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["eks-connector.amazonaws.com", "ssm.amazonaws.com"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Description="sim2real eks fidelity check: EKS connector role",
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    try:
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonEKSConnectorAgentPolicy",
        )
    except ClientError:
        pass
    return f"arn:aws:iam::{account}:role/{role_name}"


def _register_connected_cluster(ctx, *, tags_map=None, timeout_s=240):
    """RegisterCluster with a fresh connector role; returns (cluster, role_arn)."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-connected-")
    role_arn = _create_connector_role(ctx)
    kwargs = {"name": name, "connectorConfig": {"roleArn": role_arn, "provider": "OTHER"}}
    if tags_map is not None:
        kwargs["tags"] = dict(tags_map)
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))

    def attempt():
        try:
            return c.register_cluster(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in (
                "ResourcePropagationDelayException",
                "InvalidRequestException",
                "InvalidParameterException",
                "AccessDeniedException",
            ):
                return None
            raise

    resp = _wait_for(
        attempt,
        lambda r: r is not None,
        timeout_s=timeout_s,
        interval_s=5,
        desc="RegisterCluster accepted (connector role propagation)",
    )
    return resp["cluster"], role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
