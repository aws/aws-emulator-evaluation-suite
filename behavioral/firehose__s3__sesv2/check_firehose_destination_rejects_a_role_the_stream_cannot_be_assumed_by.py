"""firehose-destination-rejects-a-role-the-stream-cannot-be-assumed-by."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-destination-rejects-a-role-the-stream-cannot-be-assumed-by"
GROUP = "eventing"
SERVICES = ["firehose", "s3", "sesv2"]

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]



def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _create_bucket(ctx) -> dict[str, str]:
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_role(ctx, trust_service, inline_policy):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-xsvc-role-{trust_service.split('.')[0]}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy))
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """Detach and delete every policy, then the role; a failure raises rather than leaking."""
    iam = ctx.client("iam")
    for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _provision_stream(ctx, bucket):
    firehose_role = _create_role(
        ctx,
        "firehose.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": [bucket["arn"], f"{bucket['arn']}/*"],
                }
            ],
        },
    )
    firehose = ctx.client("firehose")
    name = _xname(ctx, "dstream")
    deadline = time.monotonic() + 90
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": firehose_role["arn"],
                    "BucketARN": bucket["arn"],
                    "Prefix": "ses-events/",
                    "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                    "CompressionFormat": "UNCOMPRESSED",
                },
                Tags=_MANAGED_TAGS,
            )
            break
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            if "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: ctx.client("firehose").delete_delivery_stream(DeliveryStreamName=name))
    desc = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"],
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
        description="delivery stream reaches ACTIVE",
    )
    return name, desc["DeliveryStreamARN"]


def _firehose_putrecordbatch_policy(stream_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["firehose:PutRecordBatch"], "Resource": stream_arn}],
    }


def _error(fn) -> tuple[str, str]:
    """(code, message) of the error fn() raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but it succeeded: {result!r}")




@tags(
    "axis:rejection",
    "cap:c3",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A Firehose event destination whose role never trusts ses.amazonaws.com is rejected at
    creation with BadRequestException naming the role, on every attempt, while the same destination
    with a correctly trusted role succeeds; only the trusted destination exists afterwards.
    """
    bucket = _create_bucket(ctx)
    stream_name, stream_arn = _provision_stream(ctx, bucket)

    wrong_trust_role = _create_role(
        ctx, "lambda.amazonaws.com", _firehose_putrecordbatch_policy(stream_arn)
    )
    right_trust_role = _create_role(
        ctx, "ses.amazonaws.com", _firehose_putrecordbatch_policy(stream_arn)
    )

    sesv2 = ctx.client("sesv2")
    config_set = ctx.unique_name("sim2real-xsvc-sesfhneg-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))

    def _destination(name: str, role_arn: str) -> dict:
        return {"ConfigurationSetName": config_set, "EventDestinationName": name,
                "EventDestination": {"Enabled": True, "MatchingEventTypes": ["SEND"],
                                     "KinesisFirehoseDestination": {
                                         "IamRoleArn": role_arn, "DeliveryStreamArn": stream_arn}}}

    # Positive control first: the same stream and config set with a role differing only in trust
    # succeeds once IAM has propagated (SES answers "could not assume" until then). Both roles
    # were created together, so once this passes the wrong-trust role has propagated too and its
    # refusal below is about its trust policy, not about propagation.
    deadline = time.monotonic() + 90
    while True:
        try:
            sesv2.create_configuration_set_event_destination(
                **_destination("sim2real-fh-right-trust", right_trust_role["arn"]))
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise AssertionError(
                f"positive control failed: a correctly-trusted role against the same real "
                f"stream was rejected: {exc.response.get('Error')!r}"
            )

    # The break: the wrong-trust role, refused synchronously and permanently (twice).
    for attempt in (1, 2):
        code, message = _error(lambda: sesv2.create_configuration_set_event_destination(
            **_destination("sim2real-fh-wrong-trust", wrong_trust_role["arn"])))
        assert code == "BadRequestException", (
            f"attempt {attempt}: a role whose trust policy never allows ses.amazonaws.com to "
            f"assume it must be rejected BadRequestException; got {code!r}"
        )
        assert message == f"Could not assume IAM role <{wrong_trust_role['arn']}>.", (
            f"attempt {attempt}: the refusal message is {message!r}")

    described = sesv2.get_configuration_set_event_destinations(ConfigurationSetName=config_set)
    names = {d["Name"] for d in described["EventDestinations"]}
    assert names == {"sim2real-fh-right-trust"}, (
        f"exactly the correctly-trusted destination may exist, the refused one must not; got "
        f"{names!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
