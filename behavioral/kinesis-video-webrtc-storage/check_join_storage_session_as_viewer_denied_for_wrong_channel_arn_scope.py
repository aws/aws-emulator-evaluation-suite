"""join-storage-session-as-viewer-denied-for-wrong-channel-arn-scope."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "join-storage-session-as-viewer-denied-for-wrong-channel-arn-scope"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-webrtc-storage"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role allowed JoinStorageSessionAsViewer on one channel's ARN joins that channel, but the same call on
    another channel fails with AccessDeniedException and the exact implicit-deny message naming that ARN."""
    channel_allowed = _create_channel_and_stream(ctx)
    channel_other = _create_channel_and_stream(ctx)
    kv = channel_allowed["kv"]

    role_name, account_id = _create_role_with_policy(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": "kinesisvideo:JoinStorageSessionAsViewer",
                "Resource": channel_allowed["channel_arn"],
            }
        ],
    )
    endpoint_other = _webrtc_endpoint(kv, channel_other["channel_arn"], "VIEWER")
    endpoint_allowed = _webrtc_endpoint(kv, channel_allowed["channel_arn"], "VIEWER")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    scoped_client_other = _assume_role_client(
        ctx, "kinesis-video-webrtc-storage", role_arn, endpoint_url=endpoint_other
    )
    scoped_client_allowed = _assume_role_client(
        ctx, "kinesis-video-webrtc-storage", role_arn, endpoint_url=endpoint_allowed
    )

    # BARRIER. IAM's inline-policy propagation returns AccessDeniedException too, so a denial
    # observed before the allowed path has ever succeeded is indistinguishable from "not yet
    # propagated". Poll the allowed path until it succeeds before trusting any denial.
    _poll(
        lambda: _joins_once_propagated(
            lambda: scoped_client_allowed.join_storage_session_as_viewer(
                channelArn=channel_allowed["channel_arn"], clientId=ctx.unique_name("viewer-")
            )
        ),
        lambda joined: joined,
        timeout_s=120.0,
        interval_s=5.0,
        description="the ARN-scoped role became able to join the allowed channel",
    )

    # Break exactly one thing: the same role, the same operation, a channel outside its Resource.
    other_code, other_message = _error(
        lambda: scoped_client_other.join_storage_session_as_viewer(
            channelArn=channel_other["channel_arn"], clientId=ctx.unique_name("viewer-")
        )
    )
    assert other_code == "AccessDeniedException", f"expected AccessDeniedException, got {other_code}"
    action = "kinesisvideo:JoinStorageSessionAsViewer"
    assert other_message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-session is not "
        f"authorized to perform: {action} on resource: {channel_other['channel_arn']} because no "
        f"identity-based policy allows the {action} action"
    ), f"JoinStorageSessionAsViewer message: {other_message!r}"

    # Effect absent, and the session did not simply die between calls: the allowed path must still
    # succeed after the refusal, so the denial is attributable to the ARN scope specifically.
    # A ClientError here fails the check: the session must not simply have died, or the denial
    # above proves nothing about the ARN scope.
    scoped_client_allowed.join_storage_session_as_viewer(
        channelArn=channel_allowed["channel_arn"], clientId=ctx.unique_name("viewer-")
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


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
    assert role_arn == f"arn:aws:iam::{account_id}:role/{role_name}", role_arn
    return role_name, account_id


def _assume_role_client(ctx, service, role_arn, timeout_s=90.0, interval_s=3.0, endpoint_url=None):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-session")["Credentials"]
            return ctx.client(
                service,
                endpoint_url=endpoint_url,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
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


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _joins_once_propagated(fn):
    """True when the call succeeds; False on the AccessDeniedException IAM propagation returns."""
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "AccessDeniedException":
            raise
        return False
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
