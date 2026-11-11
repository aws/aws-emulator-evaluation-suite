"""destination-policy-enforces-cross-account-subscription."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "destination-policy-enforces-cross-account-subscription"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With no access policy, PutSubscriptionFilter to a Logs destination is denied even for its
    owner; once any policy is attached the owner can subscribe whatever principals it names, and
    the policy document is stored exactly as supplied."""
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-behav-deststream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    _wait_stream_active(kinesis, stream_name)
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{stream_name}"

    role_arn = _create_destination_role(ctx, stream_arn)

    dest_name = ctx.unique_name("sim2real-behav-destination-")
    # PutDestination test-delivers a message with the role, whose new kinesis:PutRecord* policy
    # can take seconds to propagate through IAM, so creation is bound-polled.
    dest_resp = _put_destination_with_retry(
        logs, destinationName=dest_name, targetArn=stream_arn, roleArn=role_arn
    )
    ctx.on_cleanup(lambda: logs.delete_destination(destinationName=dest_name))
    destination_arn = dest_resp["destination"]["arn"]

    described = logs.describe_destinations(DestinationNamePrefix=dest_name)
    matches = [d for d in described["destinations"] if d["destinationName"] == dest_name]
    assert matches, "destination not found right after PutDestination"
    assert not matches[0].get("accessPolicy"), (
        "a freshly created destination should have no access policy yet"
    )

    log_group = ctx.unique_name("sim2real-behav-destlog-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    filter_name = "sim2real-owner-filter"
    # With no access policy on the destination at all, PutSubscriptionFilter is denied even
    # for the destination-owning account -- the destination's access policy is the sole
    # authorization mechanism, it does not implicitly trust the owner.
    code_before_policy, message_before_policy = _error(
        lambda: logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="",
            destinationArn=destination_arn,
        )
    )
    assert code_before_policy == "AccessDeniedException", (
        f"expected AccessDeniedException subscribing to a destination with no access policy "
        f"in place, even for the owning account, got {code_before_policy}"
    )
    assert message_before_policy == (
        f"User with accountId: {account_id} is not authorized to perform: "
        f"logs:PutSubscriptionFilter on resource: {destination_arn}"
    ), (
        f"unexpected PutSubscriptionFilter refusal message: {message_before_policy!r}"
    )
    filters_denied = logs.describe_subscription_filters(logGroupName=log_group)["subscriptionFilters"]
    assert not any(f["filterName"] == filter_name for f in filters_denied), (
        "the denied PutSubscriptionFilter call must not have created a subscription filter"
    )

    owner_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOwnAccountSubscribe",
                "Effect": "Allow",
                # PutDestinationPolicy requires the Principal to be a bare account ID, not an
                # IAM ARN like "arn:aws:iam::<id>:root".
                "Principal": {"AWS": account_id},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": destination_arn,
            }
        ],
    }
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=json.dumps(owner_policy_doc))

    described2 = logs.describe_destinations(DestinationNamePrefix=dest_name)
    matches2 = [d for d in described2["destinations"] if d["destinationName"] == dest_name]
    assert matches2, "destination missing after PutDestinationPolicy"
    stored_policy = json.loads(matches2[0]["accessPolicy"])
    assert stored_policy == owner_policy_doc, (
        f"destination policy did not round-trip exactly: stored={stored_policy} "
        f"expected={owner_policy_doc}"
    )

    # Once the policy explicitly grants the owning account, PutSubscriptionFilter succeeds.
    logs.put_subscription_filter(
        logGroupName=log_group,
        filterName=filter_name,
        filterPattern="",
        destinationArn=destination_arn,
    )
    def _cleanup_filter():
        from botocore.exceptions import ClientError

        try:
            logs.delete_subscription_filter(logGroupName=log_group, filterName=filter_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_filter)
    filters = logs.describe_subscription_filters(logGroupName=log_group)["subscriptionFilters"]
    assert any(f["filterName"] == filter_name for f in filters), (
        "owner should be able to subscribe to its own destination once the access policy "
        "explicitly grants it"
    )

    foreign_account = "111122223333"
    foreign_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": foreign_account},
                "Action": "logs:PutSubscriptionFilter",
                "Resource": destination_arn,
            }
        ],
    }
    logs.put_destination_policy(destinationName=dest_name, accessPolicy=json.dumps(foreign_policy_doc))

    described3 = logs.describe_destinations(DestinationNamePrefix=dest_name)
    matches3 = [d for d in described3["destinations"] if d["destinationName"] == dest_name]
    assert matches3, "destination missing after PutDestinationPolicy"
    stored_policy2 = json.loads(matches3[0]["accessPolicy"])
    assert stored_policy2 == foreign_policy_doc, (
        f"destination policy did not round-trip exactly: stored={stored_policy2} "
        f"expected={foreign_policy_doc}"
    )

    # A foreign-only policy does not revoke the owner's ability to subscribe: the named
    # principals govern only cross-account callers once any policy is attached.
    logs.delete_subscription_filter(logGroupName=log_group, filterName=filter_name)

    def _delete_then_create():
        from botocore.exceptions import ClientError

        try:
            logs.delete_subscription_filter(logGroupName=log_group, filterName=filter_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="[status_code=5*]",
            destinationArn=destination_arn,
        )

    _delete_then_create()
    filters_after = logs.describe_subscription_filters(logGroupName=log_group)["subscriptionFilters"]
    assert any(f["filterName"] == filter_name for f in filters_after), (
        "owner's subscription filter should have been recreated even though the destination "
        "access policy now names only a foreign account"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _put_destination_with_retry(logs, timeout_s: float = 30.0, **kwargs) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return logs.put_destination(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_exc = exc
            time.sleep(3)
    raise AssertionError(
        f"put_destination never succeeded within {timeout_s}s (last error: {last_exc})"
    )


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"kinesis stream {stream_name} never became ACTIVE")


def _create_destination_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-destrole-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"], "Resource": stream_arn}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="kinesis-put", PolicyDocument=json.dumps(inline_policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="kinesis-put")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
