"""join-storage-session-access-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "join-storage-session-access-denied-without-permission"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A caller whose IAM policy explicitly denies kinesisvideo:JoinStorageSession gets
    AccessDeniedException, while the same channel still joins successfully for a caller
    with permission (positive control)."""
    setup = _create_channel_and_stream(ctx)
    channel_arn = setup["channel_arn"]
    kv = setup["kv"]
    endpoint = _webrtc_endpoint(kv, channel_arn, "MASTER")

    role_arn = _create_role_with_policy(
        ctx,
        [
            {"Effect": "Allow", "Action": "kinesisvideo:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "kinesisvideo:JoinStorageSession", "Resource": "*"},
        ],
    )
    denied_client = _assume_role_client(ctx, "kinesis-video-webrtc-storage", role_arn, endpoint_url=endpoint)
    role_name = role_arn.rsplit("/", 1)[1]
    account_id = role_arn.split(":")[4]

    error = _client_error(lambda: denied_client.join_storage_session(channelArn=channel_arn))
    assert error.get("Code") == "AccessDeniedException", error
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-session is not authorized "
        f"to perform: kinesisvideo:JoinStorageSession on resource: {channel_arn} "
        "with an explicit deny in an identity-based policy"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: the permitted caller joins the same channel.
    control_client = ctx.client("kinesis-video-webrtc-storage", endpoint_url=endpoint)
    control_client.join_storage_session(channelArn=channel_arn)


def _create_role_with_policy(ctx, statements):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-kvsrtc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-inline-policy"
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _assume_role_client(ctx, service, role_arn, timeout_s=90.0, interval_s=3.0, endpoint_url=None):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-session")["Credentials"]
            role_creds = {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
            return ctx.client(service, endpoint_url=endpoint_url, creds=role_creds)
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role within {timeout_s}s: {last_err}")


def _webrtc_endpoint(kv, channel_arn, role):
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": ["WEBRTC"], "Role": role},
    )
    for e in resp["ResourceEndpointList"]:
        if e["Protocol"] == "WEBRTC":
            return e["ResourceEndpoint"]
    raise AssertionError(f"no WEBRTC endpoint returned for role={role}")


def _wait_channel_active(kv, channel_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_signaling_channel(ChannelARN=channel_arn)["ChannelInfo"]["ChannelStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"signaling channel never reached ACTIVE (last status={status})")


def _wait_stream_active(kv, stream_arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamARN=stream_arn)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream never reached ACTIVE (last status={status})")


def _safe_delete_channel(kv, channel_arn):
    try:
        kv.delete_signaling_channel(ChannelARN=channel_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_stream(kv, stream_arn):
    try:
        kv.delete_stream(StreamARN=stream_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_unlink(kv, channel_arn):
    try:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn, MediaStorageConfiguration={"Status": "DISABLED"}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_channel_and_stream(ctx, link_storage=True, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    channel_name = ctx.unique_name("sim2real-kvsrtc-ch-")
    stream_name = ctx.unique_name("sim2real-kvsrtc-strm-")
    channel_arn = kv.create_signaling_channel(
        ChannelName=channel_name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kv, channel_arn))
    stream_arn = kv.create_stream(
        StreamName=stream_name,
        DataRetentionInHours=retention_hours,
        Tags={"sim2real": CHECK},
    )["StreamARN"]
    ctx.on_cleanup(lambda: _safe_delete_stream(kv, stream_arn))
    _wait_channel_active(kv, channel_arn)
    _wait_stream_active(kv, stream_arn)
    if link_storage:
        kv.update_media_storage_configuration(
            ChannelARN=channel_arn,
            MediaStorageConfiguration={"StreamARN": stream_arn, "Status": "ENABLED"},
        )
        ctx.on_cleanup(lambda: _safe_unlink(kv, channel_arn))
    return {
        "kv": kv,
        "channel_arn": channel_arn,
        "stream_arn": stream_arn,
        "channel_name": channel_name,
        "stream_name": stream_name,
    }


def _client_error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises, so a
    target that accepts what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
