"""firehose-destination-delivers-two-send-events-within-the-buffering-interval."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-destination-delivers-two-send-events-within-the-buffering-interval"
GROUP = "eventing"
SERVICES = ["firehose", "s3", "sesv2"]

_BASELINE_TAG = {"Key": "sim2real-infra-dns-baseline", "Value": "true"}
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-xsvc"},
]





def _sending_domain(ctx, route53, sesv2):
    """The account's DNS baseline domain, the apex of its public hosted zone tagged
    _BASELINE_TAG, which SES has verified."""
    for page in route53.get_paginator("list_hosted_zones").paginate():
        for z in page["HostedZones"]:
            if z["Config"].get("PrivateZone"):
                continue
            zone_tags = route53.list_tags_for_resource(
                ResourceType="hostedzone", ResourceId=z["Id"].rsplit("/", 1)[-1]
            )["ResourceTagSet"]["Tags"]
            if _BASELINE_TAG in zone_tags:
                domain = z["Name"].rstrip(".")
                identity = sesv2.get_email_identity(EmailIdentity=domain)
                assert identity["VerifiedForSendingStatus"], (
                    f"the DNS baseline domain {domain!r} is not verified for sending in "
                    f"{ctx.region} (DKIM {identity['DkimAttributes']['Status']!r})"
                )
                return domain
    raise AssertionError(
        "no public hosted zone carries the DNS baseline tag, so the account has "
        "no verified domain to send from"
    )


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
    # us-east-1 is CreateBucket's own default region; passing a LocationConstraint for it
    # is rejected with InvalidLocationConstraint, so it must be omitted only there.
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
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


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
            code = e.response.get("Error", {}).get("Code")
            msg = e.response.get("Error", {}).get("Message", "")
            if code == "InvalidArgumentException" and "assume role" in msg.lower() and time.monotonic() < deadline:
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




# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:eventing",
    "concern:data-plane",
    "dp:api",
    "plane:data",
    "requires:dns-baseline",
    "timing:real-time",
)
def run(ctx) -> None:
    """A configuration set's Firehose event destination delivers both Send events to the stream's S3
    bucket as newline-delimited JSON, each with eventType Send and the sender as its source.
    """
    route53 = ctx.client("route53")
    sesv2 = ctx.client("sesv2")
    sender_domain = _sending_domain(ctx, route53, sesv2)
    sender = f"{ctx.unique_name('sim2real-')}@{sender_domain}"

    bucket = _create_bucket(ctx)
    stream_name, stream_arn = _provision_stream(ctx, bucket)

    ses_firehose_role = _create_role(
        ctx,
        "ses.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecordBatch"],
                    "Resource": stream_arn,
                }
            ],
        },
    )

    config_set = ctx.unique_name("sim2real-xsvc-sesfh-")
    sesv2.create_configuration_set(ConfigurationSetName=config_set)
    ctx.on_cleanup(lambda: sesv2.delete_configuration_set(ConfigurationSetName=config_set))

    # SES assumes the per-destination role at create time too; retry the same transient.
    deadline = time.monotonic() + 90
    while True:
        try:
            sesv2.create_configuration_set_event_destination(
                ConfigurationSetName=config_set,
                EventDestinationName="sim2real-firehose",
                EventDestination={
                    "Enabled": True,
                    "MatchingEventTypes": ["SEND"],
                    "KinesisFirehoseDestination": {
                        "IamRoleArn": ses_firehose_role["arn"],
                        "DeliveryStreamArn": stream_arn,
                    },
                },
            )
            break
        except ClientError as e:
            msg = e.response.get("Error", {}).get("Message", "")
            if "assume" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise

    markers = []
    for i in range(2):
        marker = ctx.unique_name(f"sim2real-fh-evt-{i}-")
        markers.append(marker)
        sesv2.send_email(
            FromEmailAddress=sender,
            Destination={"ToAddresses": ["success@simulator.amazonses.com"]},
            Content={
                "Simple": {
                    "Subject": {"Data": f"sim2real {CHECK} {marker}"},
                    "Body": {"Text": {"Data": marker}},
                }
            },
            ConfigurationSetName=config_set,
        )
        time.sleep(1.0)

    def _delivered_bodies():
        s3 = ctx.client("s3")
        objs = s3.list_objects_v2(Bucket=bucket["name"], Prefix="ses-events/").get("Contents", [])
        bodies = []
        for o in objs:
            bodies.append(s3.get_object(Bucket=bucket["name"], Key=o["Key"])["Body"].read().decode("utf-8"))
        return bodies

    bodies = _poll_until(
        _delivered_bodies,
        lambda bs: bs and all(m in "".join(bs) for m in markers),
        timeout_s=420,
        interval_s=15,
        description=f"Firehose delivering both Send events ({markers!r}) to S3",
    )
    joined = "".join(bodies)
    lines = [ln for ln in joined.splitlines() if ln.strip()]
    events = [json.loads(ln) for ln in lines if '"eventType"' in ln]
    marker_subjects = {e["mail"]["commonHeaders"]["subject"] for e in events}
    for marker in markers:
        assert any(marker in subj for subj in marker_subjects), (
            f"no delivered Send event's subject carries marker {marker!r}; "
            f"delivered subjects were {sorted(marker_subjects)!r}"
        )
    for e in events:
        if any(e["mail"]["commonHeaders"]["subject"].endswith(m) for m in markers):
            assert e["eventType"] == "Send", f"expected eventType 'Send', got {e['eventType']!r}"
            assert e["mail"]["source"] == sender, f"expected source {sender!r}, got {e['mail']['source']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
