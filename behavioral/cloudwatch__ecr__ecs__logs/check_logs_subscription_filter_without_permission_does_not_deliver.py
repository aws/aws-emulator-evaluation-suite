"""logs-subscription-filter-without-permission-does-not-deliver."""
from __future__ import annotations

import gzip
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-subscription-filter-without-permission-does-not-deliver"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A subscription filter whose IAM role lacks kinesis:PutRecord never delivers log events."""
    logs = ctx.client("logs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    log_group = ctx.unique_name("/sim2real/behav-subfilter-")
    logs.create_log_group(logGroupName=log_group, tags={"sim2real": "behav-subfilter-permission"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # The no-permission role is created first, so the permitted role's filter succeeding below is
    # the IAM propagation barrier for both.
    bad_stream_arn, bad_stream_name = _create_kinesis_stream(ctx)
    bad_role_arn = _create_logs_role(ctx, account_id, permit_stream_arn=None)
    good_stream_arn, good_stream_name = _create_kinesis_stream(ctx)
    good_role_arn = _create_logs_role(ctx, account_id, permit_stream_arn=good_stream_arn)

    # ---- Positive control: identical wiring, but the role IS permitted ----
    good_token = ctx.unique_name("BEHAV-WITHPERM-")
    good_created, good_code, good_err = _create_subscription_and_send(
        ctx, logs, log_group, "with-perm", good_stream_arn, good_role_arn, good_token, retry_s=60
    )
    assert good_created, (
        "positive control: subscription filter creation was rejected even though the role had "
        f"kinesis:PutRecord — last error {good_code!r}: {good_err}"
    )
    delivered = _poll_stream_for_token(ctx, good_stream_name, good_token, timeout_s=90)
    assert delivered, "positive control: log event was never delivered even though the role had kinesis:PutRecord"

    # ---- Negative path: role with a valid trust policy but NO kinesis permissions ----
    # CloudWatch Logs validates PutRecord permission for a Kinesis destination synchronously at
    # put_subscription_filter time, so the call is rejected; if it is accepted, nothing may arrive.
    bad_stream_token = ctx.unique_name("BEHAV-NOPERM-")
    created, bad_code, bad_msg = _create_subscription_and_send(
        ctx, logs, log_group, "no-perm", bad_stream_arn, bad_role_arn, bad_stream_token, retry_s=0
    )
    if not created:
        # The message names the assumed-role session CloudWatch Logs opens for the test delivery,
        # a per-call session name the check cannot know, so the text around it is asserted.
        assert bad_code == "InvalidParameterException", (
            "expected PutSubscriptionFilter to be rejected with InvalidParameterException for a "
            f"role ({bad_role_arn}) with no kinesis:PutRecord permission, but it was {bad_code!r}: {bad_msg}"
        )
        prefix = (f"Could not deliver test message to specified Kinesis stream. User: "
                  f"arn:aws:sts::{account_id}:assumed-role/{bad_role_arn.rsplit('/', 1)[1]}/")
        suffix = (f" is not authorized to perform: kinesis:PutRecord on resource: {bad_stream_arn} "
                  "because no identity-based policy allows the kinesis:PutRecord action")
        assert bad_msg.startswith(prefix) and bad_msg.endswith(suffix), (
            f"PutSubscriptionFilter must say {prefix!r}<session>{suffix!r}, got {bad_msg!r}")
    else:
        # The permitted filter forwards the same event: once it arrives there, the stream behind
        # the unpermitted role is read once.
        assert _poll_stream_for_token(ctx, good_stream_name, bad_stream_token, timeout_s=90), (
            "the permitted filter never forwarded the event sent through both filters"
        )
        assert not _poll_stream_for_token(ctx, bad_stream_name, bad_stream_token, timeout_s=0), (
            f"log event was delivered to Kinesis via a role ({bad_role_arn}) with no kinesis:PutRecord "
            "permission — the subscription filter should have failed to deliver"
        )


# ===== helpers =====
def _create_kinesis_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-stream-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "behav-subfilter-permission"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name))
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 100})
    desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
    return desc["StreamARN"], stream_name


def _create_logs_role(ctx, account_id: str, permit_stream_arn: str | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cwl2k-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringLike": {"aws:SourceArn": f"arn:aws:logs:{ctx.region}:{account_id}:*"}},
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "behav-subfilter-permission"}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        if permit_stream_arn is not None:
            iam.delete_role_policy(RoleName=role_name, PolicyName="permissions")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    if permit_stream_arn is not None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": permit_stream_arn}],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName="permissions", PolicyDocument=json.dumps(policy))

    # IAM role/policy propagation is eventually consistent: the caller retries
    # PutSubscriptionFilter for the permitted role on a bounded deadline.
    return role_arn


def _create_subscription_and_send(
    ctx, logs, log_group: str, suffix: str, destination_arn: str, role_arn: str, token: str, retry_s: float
) -> tuple[bool, str | None, str | None]:
    """Create the subscription filter and send a log event.

    Retries the InvalidParameterException a not-yet-propagated role raises for up to retry_s.
    Returns (created, last_error_code, last_error_message).
    """
    filter_name = ctx.unique_name(f"sim2real-behav-subfilter-{suffix}-")
    stream_name = ctx.unique_name(f"sim2real-behav-logstream-{suffix}-")
    logs.create_log_stream(logGroupName=log_group, logStreamName=stream_name)

    deadline = time.monotonic() + retry_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        try:
            logs.put_subscription_filter(
                logGroupName=log_group,
                filterName=filter_name,
                filterPattern="",
                destinationArn=destination_arn,
                roleArn=role_arn,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidParameterException" or time.monotonic() >= deadline:
                return False, code, exc.response["Error"].get("Message", "")
            time.sleep(2)
            continue
        ctx.on_cleanup(lambda: logs.delete_subscription_filter(logGroupName=log_group, filterName=filter_name))
        now_ms = int(time.time() * 1000)
        logs.put_log_events(
            logGroupName=log_group,
            logStreamName=stream_name,
            logEvents=[{"timestamp": now_ms, "message": f"behavioral-check {token}"}],
        )
        return True, None, None



def _poll_stream_for_token(ctx, stream_name: str, token: str, timeout_s: float) -> bool:
    kinesis = ctx.client("kinesis")
    shard_id = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["Shards"][0]["ShardId"]
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]

    # Reads up to the shard's tip (catch-up raises 30 s past timeout_s, 0.25 s apart to stay
    # under the per-shard read limit), then every 2 s until timeout_s.
    deadline = time.monotonic() + timeout_s
    while True:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=50)
        for record in resp.get("Records", []):
            try:
                payload = json.loads(gzip.decompress(record["Data"]))
            except (OSError, ValueError):
                continue
            for event in payload.get("logEvents", []):
                if token in event.get("message", ""):
                    return True
        iterator = resp.get("NextShardIterator")
        if iterator is None:
            return False
        if resp.get("MillisBehindLatest", 0) > 0:
            if time.monotonic() >= deadline + 30:
                raise AssertionError(f"{stream_name} did not reach its shard's tip within {timeout_s + 30}s")
            time.sleep(0.25)
            continue
        if time.monotonic() >= deadline:
            return False
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
