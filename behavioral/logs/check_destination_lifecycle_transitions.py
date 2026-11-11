"""destination-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "destination-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDestination creates a cross-account destination visible via
    DescribeDestinations; PutDestinationPolicy attaches an access policy; DeleteDestination
    removes the destination entirely."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # PutDestination validates that the target is actually reachable (it
    # delivers a test message through the target ARN using the given role),
    # so the target Kinesis stream must genuinely exist and the role must
    # genuinely be able to write to it.
    stream_arn = _create_active_kinesis_stream(ctx)
    role_arn = _create_role(ctx, ["logs.amazonaws.com"])
    _attach_inline_policy(
        ctx,
        role_arn,
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": stream_arn}
            ],
        },
    )

    dest_name = ctx.unique_name("sim2real-cadst-")
    target_arn = stream_arn

    put_resp = _put_destination_with_retry(logs, dest_name, target_arn, role_arn)
    destination_arn = put_resp["destination"]["arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_destination(destinationName=dest_name)))
    assert put_resp["destination"]["targetArn"] == target_arn, (
        f"expected PutDestination echo targetArn={target_arn}, got {put_resp['destination']['targetArn']}"
    )
    assert put_resp["destination"]["roleArn"] == role_arn, (
        f"expected PutDestination echo roleArn={role_arn}, got {put_resp['destination']['roleArn']}"
    )

    # Independent read: confirm DescribeDestinations agrees with PutDestination's own
    # echo, not just that a same-named row exists.
    found = _poll_until(
        lambda: _lookup_destination(logs, dest_name),
        lambda d: d is not None,
        timeout_s=30.0,
    )
    assert found["arn"] == destination_arn, (
        f"expected DescribeDestinations arn={destination_arn}, got {found['arn']}"
    )
    assert found["targetArn"] == target_arn, (
        f"expected DescribeDestinations targetArn={target_arn}, got {found['targetArn']}"
    )
    assert found["roleArn"] == role_arn, (
        f"expected DescribeDestinations roleArn={role_arn}, got {found['roleArn']}"
    )

    access_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": account_id},
                    "Action": "logs:PutSubscriptionFilter",
                    "Resource": destination_arn,
                }
            ],
        }
    )
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=access_policy)

    with_policy = _poll_until(
        lambda: _lookup_destination(logs, dest_name),
        lambda d: d is not None and d.get("accessPolicy"),
        timeout_s=30.0,
    )
    stored_policy = json.loads(with_policy["accessPolicy"])
    statement = stored_policy["Statement"][0]
    assert statement["Action"] == "logs:PutSubscriptionFilter", (
        f"expected stored accessPolicy Action='logs:PutSubscriptionFilter', got {statement['Action']!r}"
    )
    assert statement["Resource"] == destination_arn, (
        f"expected stored accessPolicy Resource={destination_arn}, got {statement['Resource']!r}"
    )
    assert statement["Principal"]["AWS"] == account_id, (
        f"expected stored accessPolicy Principal.AWS={account_id}, got {statement['Principal']!r}"
    )

    logs.delete_destination(destinationName=dest_name)
    _poll_until(
        lambda: _lookup_destination(logs, dest_name),
        lambda d: d is None,
        timeout_s=30.0,
    )


def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _lookup_destination(logs_client, dest_name: str) -> dict | None:
    next_token = None
    while True:
        kwargs = {"DestinationNamePrefix": dest_name}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = logs_client.describe_destinations(**kwargs)
        for d in resp.get("destinations", []):
            if d.get("destinationName") == dest_name:
                return d
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_role(ctx, trust_services: list[str]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-logs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_services}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return resp["Role"]["Arn"]


def _attach_inline_policy(ctx, role_arn: str, policy_doc: dict) -> None:
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    policy_name = ctx.unique_name("sim2real-logs-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    )


def _create_active_kinesis_stream(ctx) -> str:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-cadst-stream-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: _safe_call(lambda: kinesis.delete_stream(StreamName=name)))

    def _describe():
        return kinesis.describe_stream(StreamName=name)["StreamDescription"]

    desc = _poll_until(_describe, lambda d: d["StreamStatus"] == "ACTIVE", timeout_s=120.0)
    return desc["StreamARN"]


def _put_destination_with_retry(
    logs_client, dest_name: str, target_arn: str, role_arn: str, timeout_s: float = 90.0, interval_s: float = 5.0
) -> dict:
    """PutDestination delivers a test message to the target using the given
    role at creation time; IAM role/policy propagation is eventually
    consistent, so retry on the transient InvalidParameterException it raises
    while the freshly-attached permissions have not yet propagated."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return logs_client.put_destination(
                destinationName=dest_name, targetArn=target_arn, roleArn=role_arn
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
