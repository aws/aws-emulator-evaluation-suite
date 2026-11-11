"""resource-policy-denies-cross-principal-get-records."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-denies-cross-principal-get-records"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A resource policy Deny makes GetRecords fail with AccessDeniedException for a role whose
    identity policy allows it, while the owner still reads; removing the Deny restores access."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    name, stream_arn = _create_active_stream(ctx)
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-kinesis-denied-")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_doc),
        Tags=[{"Key": "sim2real", "Value": "resource-policy-denies-cross-principal-get-records"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    identity_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:GetRecords",
                    "kinesis:GetShardIterator",
                    "kinesis:DescribeStreamSummary",
                    "kinesis:ListShards",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="AllowKinesisRead", PolicyDocument=json.dumps(identity_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="AllowKinesisRead"))

    # Explicitly deny GetRecords to that role via a Kinesis resource policy. Kinesis
    # resource policies expect IAM role principals in list form
    # ({"AWS": ["arn:...:role/name"]}); Kinesis also validates that the principal ARN
    # resolves to a real IAM entity, and that validation can lag briefly behind
    # IAM's own eventual consistency for a role that was JUST created, so retry.
    resource_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyRoleGetRecords",
                "Effect": "Deny",
                "Principal": {"AWS": [role_arn]},
                "Action": "kinesis:GetRecords",
                "Resource": stream_arn,
            }
        ],
    }
    _retry_until_success(
        lambda: kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=json.dumps(resource_policy)),
        timeout_s=45.0,
    )
    ctx.on_cleanup(lambda: _delete_policy_ignore_missing(kinesis, stream_arn))

    kinesis.put_record(StreamARN=stream_arn, Data=b"owner-visible-record", PartitionKey="pk")
    shard_id = kinesis.list_shards(StreamARN=stream_arn)["Shards"][0]["ShardId"]

    # Positive control: the stream owner's own principal (not targeted by the deny)
    # can still read the record through the exact same API.
    owner_iterator = kinesis.get_shard_iterator(
        StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    owner_records = kinesis.get_records(ShardIterator=owner_iterator)["Records"]
    assert len(owner_records) == 1 and owner_records[0]["Data"] == b"owner-visible-record", (
        f"expected the owner's own GetRecords to see the record it just put, got {owner_records!r}"
    )

    creds = _assume_role_with_retry(sts, role_arn)
    denied_client = ctx.client(
        "kinesis",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # The role's identity policy allows GetShardIterator, so this succeeds once
    # the freshly-attached identity policy has propagated.
    _retry_until_success(
        lambda: denied_client.get_shard_iterator(
            StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"],
        timeout_s=45.0,
    )

    # The resource-policy Deny on GetRecords can itself take a few seconds to
    # propagate after PutResourcePolicy returns, so poll: fetch a fresh iterator
    # and attempt GetRecords on each try until the deny is enforced (or time out).
    def _attempt_denied_get_records():
        it = denied_client.get_shard_iterator(
            StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        return _outcome(lambda: denied_client.get_records(ShardIterator=it))

    code, message = _retry_until_denied(_attempt_denied_get_records, timeout_s=60.0)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-behav is not "
        f"authorized to perform: kinesis:GetRecords on resource: {stream_arn} with an explicit "
        f"deny in a resource-based policy"
    )
    assert message == expected_message, (
        f"denied GetRecords message {message!r}, expected {expected_message!r}"
    )

    # Restore: remove the Deny statement and demand the IDENTICAL denied_client.get_records
    # call now succeeds -- proving the earlier refusal was this resource policy's doing, and
    # not some permanent inability of the role to ever read this stream.
    kinesis.delete_resource_policy(ResourceARN=stream_arn)

    def _deny_revoked():
        try:
            pol = kinesis.get_resource_policy(ResourceARN=stream_arn)["Policy"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return "not-found"
            raise
        return "revoked" if "DenyRoleGetRecords" not in pol else None

    outcome = _poll_until(_deny_revoked, lambda o: o is not None, timeout_s=120.0)
    assert outcome in ("not-found", "revoked"), f"expected the Deny statement to be revoked, got {outcome!r}"

    def _attempt_allowed_get_records():
        it = denied_client.get_shard_iterator(
            StreamARN=stream_arn, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        return denied_client.get_records(ShardIterator=it)

    restored = _retry_until_success(_attempt_allowed_get_records, timeout_s=90.0)
    assert restored["Records"] and restored["Records"][0]["Data"] == b"owner-visible-record", (
        f"expected the identical get_records call to succeed once the Deny is removed, "
        f"got {restored['Records']!r}"
    )


def _create_active_stream(ctx, shard_count: int = 1) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinesis-")
    kinesis.create_stream(
        StreamName=name,
        ShardCount=shard_count,
        StreamModeDetails={"StreamMode": "PROVISIONED"},
        Tags={"sim2real": "resource-policy-denies-cross-principal-get-records"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        last_status = desc["StreamStatus"]
        if last_status == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream never became ACTIVE (last status={last_status})")


def _outcome(fn) -> tuple[str, str | None]:
    """``(code, message)`` of the ClientError ``fn`` raises, or ``("allowed", None)`` on success."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return "allowed", None


def _delete_policy_ignore_missing(kinesis, stream_arn: str) -> None:
    try:
        kinesis.delete_resource_policy(ResourceARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_err}")


def _retry_until_success(fn, timeout_s: float = 45.0, interval_s: float = 3.0):
    """Poll a call that is expected to eventually succeed once a freshly-attached
    IAM identity policy has propagated (IAM authorization is eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"call never succeeded within {timeout_s}s (last error: {last_err})")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Poll `probe()` until `predicate` accepts it; raises (never returns a stale last value)
    if the deadline passes first."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_until_denied(fn, timeout_s: float = 60.0, interval_s: float = 3.0) -> tuple[str, str | None]:
    """Poll a call that is expected to eventually be denied once a freshly-attached
    resource policy Deny statement has propagated; returns the last ``(code, message)``."""
    deadline = time.monotonic() + timeout_s
    last = ("allowed", None)
    while time.monotonic() < deadline:
        last = fn()
        if last[0] == "AccessDeniedException":
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
