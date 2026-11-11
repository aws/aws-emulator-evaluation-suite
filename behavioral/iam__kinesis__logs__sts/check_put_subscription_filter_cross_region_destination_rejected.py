"""put-subscription-filter-cross-region-destination-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-subscription-filter-cross-region-destination-rejected"
GROUP = "subscription-filters"
SERVICES = ["iam", "kinesis", "logs", "sts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter to a destination in another Region fails with
    InvalidParameterException and creates no filter; the same group can still subscribe to a
    same-Region destination (positive control)."""
    logs_home = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    home_region = ctx.region
    other_region = "us-west-2" if home_region != "us-west-2" else "us-east-1"

    role_arn = _create_destination_role(ctx)

    home_stream_arn = _create_stream(ctx, home_region)
    _grant_stream_put(ctx, role_arn, home_stream_arn)
    home_dest_name = ctx.unique_name("sim2real-behav-psfcr-destsame-")
    home_dest_arn = _put_destination_with_retry(
        ctx.client("logs", region=home_region),
        destinationName=home_dest_name,
        targetArn=home_stream_arn,
        roleArn=role_arn,
    )
    ctx.on_cleanup(
        _teardown(
            lambda: ctx.client("logs", region=home_region).delete_destination(
                destinationName=home_dest_name
            ),
            "InvalidParameterException",
        )
    )
    _put_owner_access_policy(
        ctx.client("logs", region=home_region), home_dest_name, home_dest_arn, account_id
    )

    other_stream_arn = _create_stream(ctx, other_region)
    _grant_stream_put(ctx, role_arn, other_stream_arn)
    other_dest_name = ctx.unique_name("sim2real-behav-psfcr-destother-")
    other_dest_arn = _put_destination_with_retry(
        ctx.client("logs", region=other_region),
        destinationName=other_dest_name,
        targetArn=other_stream_arn,
        roleArn=role_arn,
    )
    ctx.on_cleanup(
        _teardown(
            lambda: ctx.client("logs", region=other_region).delete_destination(
                destinationName=other_dest_name
            ),
            "InvalidParameterException",
        )
    )
    _put_owner_access_policy(
        ctx.client("logs", region=other_region), other_dest_name, other_dest_arn, account_id
    )

    group_name = ctx.unique_name("sim2real-behav-psfcr-group-")
    logs_home.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs_home.delete_log_group(logGroupName=group_name))

    # Positive control: a same-Region destination accepts the subscription.
    good_filter_name = ctx.unique_name("sim2real-behav-psfcr-filter-good-")
    _put_filter_with_retry(logs_home, group_name, good_filter_name, home_dest_arn)
    ctx.on_cleanup(
        _teardown(
            lambda: logs_home.delete_subscription_filter(
                logGroupName=group_name, filterName=good_filter_name
            ),
            "ResourceNotFoundException",
        )
    )
    filters = logs_home.describe_subscription_filters(logGroupName=group_name)[
        "subscriptionFilters"
    ]
    assert any(f["filterName"] == good_filter_name for f in filters), (
        f"positive-control filter {good_filter_name!r} missing from {filters!r}"
    )

    bad_filter_name = ctx.unique_name("sim2real-behav-psfcr-filter-bad-")
    code, message = _error(
        lambda: logs_home.put_subscription_filter(
            logGroupName=group_name,
            filterName=bad_filter_name,
            filterPattern="",
            destinationArn=other_dest_arn,
        )
    )
    assert code == "InvalidParameterException", (
        f"cross-Region PutSubscriptionFilter returned {code!r}, expected InvalidParameterException"
    )
    assert message == "Logical destination should be in the same region as caller region", (
        f"unexpected cross-Region PutSubscriptionFilter message: {message!r}"
    )

    filters_after = logs_home.describe_subscription_filters(logGroupName=group_name)[
        "subscriptionFilters"
    ]
    names_after = {f["filterName"] for f in filters_after}
    assert bad_filter_name not in names_after, (
        f"cross-Region destination filter must not persist, found {filters_after!r}"
    )
    assert good_filter_name in names_after, (
        f"positive-control filter vanished after the rejected call: {filters_after!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _put_filter_with_retry(logs, group_name: str, filter_name: str, destination_arn: str) -> None:
    """Retry InvalidParameterException while the destination role's policy propagates."""
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=group_name,
                filterName=filter_name,
                filterPattern="",
                destinationArn=destination_arn,
            )
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterException":
                last_err = err
                time.sleep(3.0)
                continue
            raise
    raise AssertionError(f"could not put subscription filter in time: {last_err}")


def _put_destination_with_retry(logs, timeout_s: float = 60.0, **kwargs) -> str:
    """PutDestination, retried while the role's trust/policy propagates; returns the ARN."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return logs.put_destination(**kwargs)["destination"]["arn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"PutDestination never succeeded within {timeout_s}s (last: {last_exc})")


def _create_stream(ctx, region: str) -> str:
    """A tiny on-demand Kinesis stream in ``region``; returns its ARN once ACTIVE."""
    kinesis = ctx.client("kinesis", region=region)
    stream_name = ctx.unique_name("sim2real-behav-psfcr-stream-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(
        _teardown(
            lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True),
            "ResourceNotFoundException",
        )
    )
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3.0)
    raise AssertionError(f"kinesis stream {stream_name!r} never became ACTIVE")


def _put_owner_access_policy(logs, dest_name: str, dest_arn: str, account_id: str) -> None:
    """Grant the owning account PutSubscriptionFilter on its own destination."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": dest_arn,
            }
        ],
    }
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=json.dumps(policy))


def _create_destination_role(ctx) -> str:
    """An IAM role the Logs service may assume to deliver to a subscription destination."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-psfcr-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _grant_stream_put(ctx, role_arn: str, stream_arn: str) -> None:
    """Allow ``role_arn`` to PutRecord(s) onto ``stream_arn`` via an inline policy."""
    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    policy_name = ctx.unique_name("sim2real-behav-psfcr-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kinesis:PutRecord", "kinesis:PutRecords"],
                        "Resource": stream_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
            "NoSuchEntity",
        )
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
