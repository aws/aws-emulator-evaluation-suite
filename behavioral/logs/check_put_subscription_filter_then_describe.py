"""put-subscription-filter-then-describe."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_on_invalid_parameter(fn, *, timeout_s=45, interval_s=3.0):
    """Retry fn() on InvalidParameterException to absorb IAM role propagation lag."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_subscription_destination(ctx, tag):
    """Create an active Kinesis stream and an IAM role logs.amazonaws.com can PutRecord with.
    CloudWatch Logs delivers a test record synchronously, so both must be reachable.
    """
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stream_name = ctx.unique_name(f"sim2real-behav-kstream-{tag}-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(
        lambda _n=stream_name: kinesis.delete_stream(StreamName=_n, EnforceConsumerDeletion=True)
    )
    _poll_until(
        lambda: kinesis.describe_stream(StreamName=stream_name)["StreamDescription"],
        lambda d: d["StreamStatus"] == "ACTIVE",
        timeout_s=90,
        interval_s=2.0,
        description=f"Kinesis stream {stream_name} becomes ACTIVE",
    )
    stream_arn = f"arn:aws:kinesis:{ctx.region}:{account}:stream/{stream_name}"

    role_name = ctx.unique_name(f"sim2real-behav-role-{tag}-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))

    def _teardown_role(rn=role_name, _iam=iam):
        try:
            _iam.delete_role_policy(RoleName=rn, PolicyName="allow-put-record")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        _iam.delete_role(RoleName=rn)

    ctx.on_cleanup(_teardown_role)
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-put-record",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": stream_arn}
                ],
            }
        ),
    )
    role_arn = f"arn:aws:iam::{account}:role/{role_name}"
    return stream_arn, role_arn


CHECK = "put-subscription-filter-then-describe"
GROUP = 'subscription-filters'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter filters are listed by DescribeSubscriptionFilters and removable via Delete.
    The per-group quota is measured; a rejected filter never attaches, and freeing a slot makes
    the identical call succeed.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-sub-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    # A same-account Kinesis destination is validated synchronously with a test record,
    # so the role's trust/permissions must have propagated.
    stream_arn, role_arn = _create_subscription_destination(ctx, "subfilter")

    def _put(name, pattern="ERROR"):
        return svc.put_subscription_filter(
            logGroupName=group,
            filterName=name,
            filterPattern=pattern,
            destinationArn=stream_arn,
            roleArn=role_arn,
        )

    # The model docs say the quota is two but AWS accepts more, so measure it,
    # bounded by a ceiling so a misbehaving target cannot loop forever.
    _MAX_PROBE = 20
    accepted_names = []
    overflow_name = None
    overflow_code = None
    overflow_message = None
    for i in range(_MAX_PROBE):
        name = ctx.unique_name(f"sim2real-behav-subf-{i}-")
        try:
            if i == 0:
                _retry_on_invalid_parameter(lambda: _put(name))
            else:
                _put(name)
            accepted_names.append(name)
        except ClientError as exc:
            overflow_code = exc.response.get("Error", {}).get("Code")
            overflow_message = exc.response.get("Error", {}).get("Message")
            overflow_name = name
            break

    assert overflow_code is not None, (
        f"expected a limit-exceeded rejection within {_MAX_PROBE} filters, but all succeeded"
    )
    assert overflow_code == "LimitExceededException", f"expected LimitExceededException, got {overflow_code!r}"
    assert overflow_message == "Resource limit exceeded.", f"unexpected message: {overflow_message!r}"
    assert len(accepted_names) >= 1, "expected at least 1 filter accepted before the quota hit"

    desc = svc.describe_subscription_filters(logGroupName=group)
    names = {f["filterName"] for f in desc.get("subscriptionFilters", [])}
    assert names == set(accepted_names), f"expected exactly the accepted filters listed, got {names!r}"
    assert overflow_name not in names, f"rejected filter {overflow_name!r} appeared in listing {names!r}"

    # Freeing a slot makes the identical call succeed: the rejection tracked the quota.
    svc.delete_subscription_filter(logGroupName=group, filterName=accepted_names[0])
    _put(overflow_name, pattern="INFO")
    attached_after_restore = {
        f["filterName"]
        for f in svc.describe_subscription_filters(logGroupName=group).get("subscriptionFilters", [])
    }
    expected_after_restore = set(accepted_names[1:]) | {overflow_name}
    assert attached_after_restore == expected_after_restore, (
        f"expected restored capacity to admit the identical call, got {attached_after_restore!r}"
    )

    for fname in accepted_names[1:] + [overflow_name]:
        svc.delete_subscription_filter(logGroupName=group, filterName=fname)
    desc_after = svc.describe_subscription_filters(logGroupName=group)
    assert desc_after.get("subscriptionFilters", []) == [], "subscription filters still listed after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
