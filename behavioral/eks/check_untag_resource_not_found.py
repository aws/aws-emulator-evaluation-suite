"""untag-resource-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

def _cluster_arn(ctx, name):
    """A well-formed EKS cluster ARN in this account/region for a cluster name."""
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:eks:{ctx.region}:{account}:cluster/{name}"

CHECK = "untag-resource-not-found"
GROUP = 'error-semantics'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on a well-formed ARN of a nonexistent cluster fails with NotFoundException "Resource was
    not found", while on a real connected cluster it removes the key, as ListTagsForResource shows."""
    c = ctx.client("eks")

    created = {"sim2real-behav": "present"}
    cluster, _role = _register_connected_cluster(ctx, tags_map=created)
    arn = cluster.get("arn")
    assert arn, f"RegisterCluster returned no arn to tag: {cluster!r}"
    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == created, f"ListTagsForResource {listed!r} != {created!r}"

    c.untag_resource(resourceArn=arn, tagKeys=["sim2real-behav"])
    listed = c.list_tags_for_resource(resourceArn=arn).get("tags", {})
    assert listed == {}, f"positive control: UntagResource left {listed!r}, expected {{}}"

    bogus_arn = _cluster_arn(ctx, ctx.unique_name("sim2real-behav-no-cluster-"))
    code, msg = _expect_error(
        lambda: c.untag_resource(resourceArn=bogus_arn, tagKeys=["sim2real-behav-absent"])
    )
    assert code == "NotFoundException", code
    assert msg == "Resource was not found", msg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
