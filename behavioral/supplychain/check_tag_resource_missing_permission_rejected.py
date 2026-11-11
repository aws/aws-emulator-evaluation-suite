"""tag-resource-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]

# AWS Supply Chain (service prefix "scn") is not available in every region; real AWS rejects
# CreateInstance in us-west-2 with ValidationException "Amazon Connect Decisions is not supported
# in us-west-2". us-east-1 is where the service launched and remains supported.
_SC_REGION = "us-east-1"
_SESSION_NAME = "sim2real-behavioral"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A principal assuming an IAM role with no attached permissions gets AccessDeniedException
    calling TagResource (implicit deny), the tag is not applied, while the check's own
    credentials (which do have permission) can tag the same resource successfully."""
    sc = ctx.client("supplychain", region=_SC_REGION)
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    instance_id = _create_active_instance(ctx, sc)
    account_id = sts.get_caller_identity()["Account"]
    instance_arn = f"arn:aws:scn:{_SC_REGION}:{account_id}:instance/{instance_id}"

    role_name = ctx.unique_name("sim2real-sc-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real behavioral check: intentionally has no permissions",
    )["Role"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))

    unauthorized_client = _assume_role_client(ctx, sts, role["Arn"])

    code, message = _error(
        lambda: unauthorized_client.tag_resource(resourceArn=instance_arn, tags={"team": "sim2real"})
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} is not authorized "
        f"to perform: scn:TagResource on resource: {instance_arn} because no identity-based policy "
        "allows the scn:TagResource action"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    tags_after_denied = sc.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert "team" not in tags_after_denied, "tag was applied despite the denied caller"

    sc.tag_resource(resourceArn=instance_arn, tags={"team": "sim2real"})
    tags_after_control = sc.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert tags_after_control.get("team") == "sim2real", (
        f"expected tag 'team=sim2real' applied by the permitted caller, got {tags_after_control!r}"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _assume_role_client(ctx, sts, role_arn):
    """IAM role trust propagation can lag briefly; retry assume-role for a bit before giving up.
    The client is built through ctx.client with the assumed identity, so it reaches the same
    target as the check's own supplychain client."""
    creds = _poll_until(
        lambda: _try_assume(sts, role_arn, _SESSION_NAME),
        lambda c: c is not None,
        timeout_s=30.0,
        interval_s=3.0,
    )
    return ctx.client(
        "supplychain",
        region=_SC_REGION,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _try_assume(sts, role_arn, session_name):
    try:
        return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
    except ClientError:
        return None


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check"
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
