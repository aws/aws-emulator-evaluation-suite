"""e2e-subscription-filter-invalid-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-subscription-filter-invalid-role-rejected"
GROUP = "e2e"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSubscriptionFilter rejects a Kinesis roleArn that logs.amazonaws.com cannot assume and
    persists no filter, while a correctly trusted role on the same group succeeds (control).
    """
    logs = ctx.client("logs")
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")

    log_group = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-kds-")
    good_role_name = ctx.unique_name("sim2real-behav-good-role-")
    bad_role_name = ctx.unique_name("sim2real-behav-bad-role-")
    good_filter_name = ctx.unique_name("sim2real-behav-good-filt-")
    bad_filter_name = ctx.unique_name("sim2real-behav-bad-filt-")

    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(ctx, stream_name)
    stream_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
        "StreamARN"
    ]

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    wrong_trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )

    good_role_arn = iam.create_role(
        RoleName=good_role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=good_role_name))
    iam.put_role_policy(
        RoleName=good_role_name,
        PolicyName="kinesis-write",
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
        lambda: iam.delete_role_policy(RoleName=good_role_name, PolicyName="kinesis-write")
    )

    # CloudWatch Logs cannot assume this role to send its delivery-validation test message.
    bad_role_arn = iam.create_role(
        RoleName=bad_role_name,
        AssumeRolePolicyDocument=wrong_trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=bad_role_name))
    iam.put_role_policy(
        RoleName=bad_role_name,
        PolicyName="kinesis-write",
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
        lambda: iam.delete_role_policy(RoleName=bad_role_name, PolicyName="kinesis-write")
    )

    _wait_role_usable(ctx, good_role_name)
    _wait_role_usable(ctx, bad_role_name)

    # Positive control: correctly-trusted, correctly-permissioned role succeeds.
    _put_subscription_filter_with_retry(
        ctx, log_group, good_filter_name, stream_arn, good_role_arn
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(
            logGroupName=log_group, filterName=good_filter_name
        )
    )
    filters = logs.describe_subscription_filters(logGroupName=log_group)[
        "subscriptionFilters"
    ]
    assert any(f["filterName"] == good_filter_name for f in filters), (
        f"expected {good_filter_name!r} in DescribeSubscriptionFilters after a correctly-trusted, "
        f"correctly-permissioned PutSubscriptionFilter succeeded; got {filters!r}"
    )

    # Negative: role with the wrong trust relationship is rejected.
    code, message = _error(
        lambda: logs.put_subscription_filter(
            logGroupName=log_group,
            filterName=bad_filter_name,
            filterPattern="",
            destinationArn=stream_arn,
            roleArn=bad_role_arn,
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a roleArn CloudWatch Logs cannot assume "
        f"(trust policy grants ec2.amazonaws.com, not logs.amazonaws.com); got {code!r}"
    )
    assert message == (
        "Could not deliver test message to specified Kinesis stream. "
        "Check if the given Kinesis stream is in ACTIVE state."
    ), (
        f"unexpected PutSubscriptionFilter message for an unassumable roleArn: {message!r}"
    )

    filters = logs.describe_subscription_filters(logGroupName=log_group)[
        "subscriptionFilters"
    ]
    assert all(f["filterName"] != bad_filter_name for f in filters), (
        f"the rejected filter {bad_filter_name!r} must not have been persisted; "
        f"DescribeSubscriptionFilters returned {filters!r}"
    )



def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2.0)
    raise AssertionError(f"kinesis stream {stream_name} never became ACTIVE")


def _wait_role_usable(ctx, role_name: str, timeout_s: float = 30.0) -> None:
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError:
            time.sleep(2.0)
    raise AssertionError(f"role {role_name} never became visible")


def _put_subscription_filter_with_retry(
    ctx, log_group: str, filter_name: str, dest_arn: str, role_arn: str, timeout_s: float = 60.0
) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            logs.put_subscription_filter(
                logGroupName=log_group,
                filterName=filter_name,
                filterPattern="",
                destinationArn=dest_arn,
                roleArn=role_arn,
            )
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"PutSubscriptionFilter never succeeded: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
