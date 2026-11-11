"""cluster-tag-round-trip-and-untag."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-tag-round-trip-and-untag"
GROUP = 'state'
SERVICES = ['eks']


# A connected cluster is used because it is the cheapest resource in EKS that
# owns a real taggable ARN: no control plane, no EC2, no hourly charge.


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
        Description="candidates_09 eks fidelity check: EKS connector role",
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
    if tags_map:
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creation tags are echoed by RegisterCluster, DescribeCluster and ListTagsForResource alike.
    TagResource overwrites an existing key, and UntagResource removes only the named keys
    (an absent key is a no-op)."""
    c = ctx.client("eks")
    created = {"env": "sim2real", "owner": "candidates-09", "keep": "yes"}
    cluster, _role = _register_connected_cluster(ctx, tags_map=created)
    name = cluster["name"]
    arn = cluster.get("arn")
    assert arn, f"RegisterCluster returned no arn to tag: {cluster!r}"

    assert cluster.get("tags") == created, (
        f"RegisterCluster echoed tags {cluster.get('tags')!r}, expected {created!r}"
    )
    described = c.describe_cluster(name=name)["cluster"]
    assert described.get("tags") == created, (
        f"DescribeCluster.tags {described.get('tags')!r} != {created!r}"
    )

    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == created, f"ListTagsForResource {listed!r} != {created!r}"

    c.tag_resource(resourceArn=arn, tags={"added": "1", "owner": "candidates-09-v2"})
    expected = {
        "env": "sim2real",
        "owner": "candidates-09-v2",
        "keep": "yes",
        "added": "1",
    }
    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == expected, (
        f"after TagResource, ListTagsForResource {listed!r} != {expected!r} "
        f"(overwrite of 'owner' and addition of 'added' must both land)"
    )
    assert c.describe_cluster(name=name)["cluster"].get("tags") == expected, (
        "DescribeCluster.tags disagrees with ListTagsForResource after TagResource"
    )

    c.untag_resource(resourceArn=arn, tagKeys=["env", "added"])
    expected = {"owner": "candidates-09-v2", "keep": "yes"}
    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == expected, (
        f"after UntagResource(['env','added']) tags are {listed!r}, expected "
        f"{expected!r} -- untagging must not clear unrelated keys"
    )

    c.untag_resource(resourceArn=arn, tagKeys=["never-set"])
    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == expected, (
        f"untagging an absent key mutated the tag map: {listed!r} != {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
