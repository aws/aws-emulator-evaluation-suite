"""cluster-tags-unicode-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "cluster-tags-unicode-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag values set by TagResource on a connected cluster come back from ListTagsForResource
    identical in content and length, also on a later repeated read.
    """
    eks = ctx.client("eks")
    cluster, _role_arn = _register_connected_cluster(ctx)
    arn = cluster["arn"]

    tag_value = "日本語テスト Ключ-Значение Δοκιμή café 你好世界 test_value.1:2/3=4+5-6@7"
    eks.tag_resource(resourceArn=arn, tags={"unicode-value": tag_value})

    read_tags = eks.list_tags_for_resource(resourceArn=arn)["tags"]
    assert read_tags["unicode-value"] == tag_value, (
        f"tag value round-trip mismatch: wrote {tag_value!r}, read back "
        f"{read_tags.get('unicode-value')!r}"
    )
    assert len(read_tags["unicode-value"]) == len(tag_value), (
        f"tag value length changed on round-trip: wrote {len(tag_value)} codepoints, read "
        f"back {len(read_tags['unicode-value'])}"
    )

    # Freeze detector: repeated independent reads over a few seconds must keep returning the
    # identical value, ruling out lazy/late normalization applied asynchronously after the write.
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        time.sleep(1)
        read_again = eks.list_tags_for_resource(resourceArn=arn)["tags"]
        assert read_again["unicode-value"] == tag_value, (
            f"tag value drifted on later read: expected {tag_value!r}, got "
            f"{read_again.get('unicode-value')!r}"
        )


def _wait_for(fn, pred, *, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
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
    role_name = ctx.unique_name("sim2real-eks-connector-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["eks-connector.amazonaws.com", "ssm.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    try:
        iam.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSConnectorAgentPolicy"
        )
    except ClientError:
        pass
    return f"arn:aws:iam::{account}:role/{role_name}"


def _register_connected_cluster(ctx, timeout_s=240):
    """RegisterCluster with a fresh connector role; returns (cluster, role_arn)."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-connected-")
    role_arn = _create_connector_role(ctx)
    kwargs = {"name": name, "connectorConfig": {"roleArn": role_arn, "provider": "OTHER"}}
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
