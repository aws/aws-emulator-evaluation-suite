"""get-images-not-authorized-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-images-not-authorized-without-permission"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

NO_FRAGMENTS = ("ResourceNotFoundException", "No fragments found in the stream for the GetImages request.")


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity with an explicit Deny on kinesisvideo:GetImages for one stream fails GetImages with
    AccessDeniedException but still lists fragments, while the stream owner's GetImages fails only for
    absent fragments."""
    ctx.client("kinesisvideo")
    iam = ctx.client("iam")
    stream = _create_active_stream(ctx, retention_hours=1)

    user_name = ctx.unique_name("sim2real-kvam-deny-")
    iam.create_user(UserName=user_name)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBaseline",
                "Effect": "Allow",
                "Action": [
                    "kinesisvideo:GetDataEndpoint",
                    "kinesisvideo:DescribeStream",
                    "kinesisvideo:ListFragments",
                    "kinesisvideo:GetImages",
                ],
                "Resource": "*",
            },
            {
                "Sid": "DenyGetImages",
                "Effect": "Deny",
                "Action": "kinesisvideo:GetImages",
                "Resource": stream["arn"],
            },
        ],
    }
    policy_name = "sim2real-deny-getimages"
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    creds = {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    }

    sts_restricted = ctx.client("sts", creds=creds)
    _poll_until(
        lambda: _sts_ok(sts_restricted), lambda ok: ok, timeout_s=60, interval_s=3,
        description="new IAM access key recognized by STS",
    )

    kv_restricted = ctx.client("kinesisvideo", creds=creds)
    endpoint_get_images = kv_restricted.get_data_endpoint(
        StreamName=stream["name"], APIName="GET_IMAGES"
    )["DataEndpoint"]
    endpoint_list_fragments = kv_restricted.get_data_endpoint(
        StreamName=stream["name"], APIName="LIST_FRAGMENTS"
    )["DataEndpoint"]
    media_images = ctx.client(
        "kinesis-video-archived-media", endpoint_url=endpoint_get_images, creds=creds
    )
    media_fragments = ctx.client(
        "kinesis-video-archived-media", endpoint_url=endpoint_list_fragments, creds=creds
    )

    now = time.time()

    def _images_error():
        return _error(lambda: media_images.get_images(
            StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
            StartTimestamp=now - 10, EndTimestamp=now, Format="JPEG",
        ))

    # An explicit Deny can lag briefly behind the access key becoming usable at all (STS already
    # confirms recognition above), so poll the denied call until the denial code appears.
    denied = (
        "AccessDeniedException",
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"kinesisvideo:GetImages on resource: {stream['name']}",
    )
    err = _poll_until(
        _images_error, lambda e: e[0] == denied[0], timeout_s=60, interval_s=3,
        description="GetImages refused with AccessDeniedException for the denied identity",
    )
    assert err == denied, f"expected {denied!r} for the explicitly-denied action, got {err!r}"

    # positive control 1: the SAME restricted identity can still call a non-denied action.
    control_resp = media_fragments.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
        },
    )
    assert control_resp["Fragments"] == [], (
        f"expected the same restricted identity's ListFragments (not denied) to succeed with no "
        f"fragments on this fresh stream, got {control_resp['Fragments']!r}"
    )

    # positive control 2: the account's own (undenied) credentials can still call GetImages --
    # it is rejected too, but on fragment absence, NOT AccessDeniedException, proving the denial
    # above is scoped to the restricted identity.
    media_full = _archived_media_client(ctx, stream["name"], "GET_IMAGES")
    full_err = _error(lambda: media_full.get_images(
        StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
        StartTimestamp=now - 10, EndTimestamp=now, Format="JPEG",
    ))
    assert full_err == NO_FRAGMENTS, (
        f"expected the account's own credentials to hit {NO_FRAGMENTS!r} (not "
        f"AccessDeniedException), got {full_err!r}"
    )


def _sts_ok(sts_client) -> bool:
    try:
        sts_client.get_caller_identity()
        return True
    except ClientError:
        return False


def _error(fn):
    """The (code, message) AWS refuses ``fn`` with; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_stream_active(kv, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamName=name)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} never reached ACTIVE (last status={status})")


def _create_active_stream(ctx, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvam-")
    resp = kv.create_stream(
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/x-matroska"
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
