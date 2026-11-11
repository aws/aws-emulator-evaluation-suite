"""tag-resource-contract-limits-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-contract-limits-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

# Modelled EKS tag limits: TagMap {1..50}, TagKey {1..128}, TagValue {0..256}. They are fixed
# properties of the API shape, not account quotas.
_MAX_TAGS = 50
_MAX_KEY = 128
_MAX_VALUE = 256


def _expect_error(fn):
    """Call fn, require that it raises, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _validation_message(rendered_value, constraint):
    """The tagging front end's map-constraint refusal: a JSON document wrapped in the
    message string, with each single quote backslash-escaped."""
    q = "\\'"
    return (
        '{"message": "1 validation error detected: Value '
        f"{q}{rendered_value}{q} at {q}addedTags{q} failed to satisfy constraint: "
        f'{constraint}"}}'
    )


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


def _register_connected_cluster(ctx, *, timeout_s=240):
    """RegisterCluster with a fresh connector role; returns (cluster, role_arn)."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-connected-")
    role_arn = _create_connector_role(ctx)
    ctx.on_cleanup(lambda: c.deregister_cluster(name=name))

    def attempt():
        try:
            return c.register_cluster(
                name=name,
                connectorConfig={"roleArn": role_arn, "provider": "OTHER"},
            )
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource accepts tag count, key and value at their modelled maxima and refuses one over.

    Each refusal is BadRequestException with the exact message and leaves the tag map unchanged.
    """
    c = ctx.client("eks")
    # A connected cluster gives a real taggable EKS ARN with no control plane or EC2. Only the
    # above-max side is tested: botocore rejects a below-min value client-side.
    cluster, _role = _register_connected_cluster(ctx)
    arn = cluster.get("arn")
    assert arn, f"RegisterCluster returned no arn to tag: {cluster!r}"
    assert c.list_tags_for_resource(resourceArn=arn).get("tags", {}) == {}, (
        "a cluster registered without tags must start with an empty tag map"
    )

    def current():
        return c.list_tags_for_resource(resourceArn=arn).get("tags", {})

    # --- Control 1: exactly the modelled maximum number of tags is accepted.
    at_max = {f"k{i:02d}": str(i) for i in range(_MAX_TAGS)}
    assert len(at_max) == _MAX_TAGS, len(at_max)
    c.tag_resource(resourceArn=arn, tags=at_max)
    assert current() == at_max, (
        f"TagResource with exactly {_MAX_TAGS} tags did not round-trip: {current()!r}"
    )
    c.untag_resource(resourceArn=arn, tagKeys=sorted(at_max))
    assert current() == {}, f"untagging all {_MAX_TAGS} keys left {current()!r}"

    # --- Limit 1: one tag over the maximum map size.
    over_max = {f"k{i:02d}": str(i) for i in range(_MAX_TAGS + 1)}
    code, msg = _expect_error(lambda: c.tag_resource(resourceArn=arn, tags=over_max))
    assert code == "BadRequestException", (
        f"TagResource with {_MAX_TAGS + 1} tags (TagMap max is {_MAX_TAGS}) -> "
        f"{code}: {msg}; expected BadRequestException"
    )
    assert msg == f"The resultant tag set must not have more than {_MAX_TAGS} user tags.", msg
    assert current() == {}, (
        f"a refused over-limit TagResource partially applied: {current()!r}"
    )

    # --- Limit 2: tag key one character over TagKey max.
    long_key = "k" * (_MAX_KEY + 1)
    code, msg = _expect_error(
        lambda: c.tag_resource(resourceArn=arn, tags={long_key: "v"})
    )
    assert code == "BadRequestException", (
        f"TagResource with a {_MAX_KEY + 1}-char key (TagKey max is {_MAX_KEY}) -> "
        f"{code}: {msg}; expected BadRequestException"
    )
    assert msg == _validation_message(
        f"{{{long_key}=v}}",
        f"Map keys must satisfy constraint: [Member must have length less than or equal to "
        f"{_MAX_KEY}, Member must have length greater than or equal to 1]",
    ), msg
    assert current() == {}, f"a refused over-long key was stored: {current()!r}"

    # --- Limit 3: tag value one character over TagValue max.
    long_value = "v" * (_MAX_VALUE + 1)
    code, msg = _expect_error(
        lambda: c.tag_resource(resourceArn=arn, tags={"ok": long_value})
    )
    assert code == "BadRequestException", (
        f"TagResource with a {_MAX_VALUE + 1}-char value (TagValue max is "
        f"{_MAX_VALUE}) -> {code}: {msg}; expected BadRequestException"
    )
    assert msg == _validation_message(
        f"{{ok={long_value}}}",
        f"Map value must satisfy constraint: [Member must have length less than or equal to "
        f"{_MAX_VALUE}, Member must have length greater than or equal to 0]",
    ), msg
    assert current() == {}, f"a refused over-long value was stored: {current()!r}"

    # --- Control 2: key and value EXACTLY at their maxima are accepted.
    boundary = {"k" * _MAX_KEY: "v" * _MAX_VALUE}
    c.tag_resource(resourceArn=arn, tags=boundary)
    assert current() == boundary, (
        f"a {_MAX_KEY}-char key with a {_MAX_VALUE}-char value must be accepted; "
        f"got {current()!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
