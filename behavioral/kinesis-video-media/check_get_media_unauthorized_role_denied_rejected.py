"""get-media-unauthorized-role-denied-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-unauthorized-role-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-media"]

_MEDIA_CONFIG = Config(read_timeout=20, connect_timeout=10, retries={"max_attempts": 1})


@tags("axis:rejection", "cap:c6", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role granted kinesisvideo:GetMedia can call it, and after an explicit Deny is attached the same
    role fails with AccessDeniedException and its exact message, while the unrestricted caller keeps
    getting 200."""
    stream = _create_active_stream(ctx)
    admin_media = _media_client_for(ctx, stream_name=stream["name"])

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-kvm-deny-")
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
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    allow_policy_name = "allow-get-media"
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "kinesisvideo:GetMedia",
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=allow_policy_name,
        PolicyDocument=json.dumps(allow_policy),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, allow_policy_name))

    deny_policy_name = "deny-get-media"
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "kinesisvideo:GetMedia",
                "Resource": "*",
            }
        ],
    }

    session_name = ctx.unique_name("sim2real-behav-kvm-session-")
    creds = _wait_for_assumable_role(sts, role_arn, session_name)

    restricted_media = ctx.client(
        "kinesis-video-media",
        endpoint_url=admin_media.meta.endpoint_url,
        config=_MEDIA_CONFIG,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    # Positive control, before the deny exists: the identity policy alone grants GetMedia, so the
    # real call must succeed for this exact role. Bounded poll for policy propagation.
    before = _poll_until(
        lambda: _get_media_error(restricted_media, stream["name"]),
        lambda c: c["Code"] == "UNEXPECTED_SUCCESS",
        timeout_s=90.0, interval_s=3.0,
    )
    assert before["Code"] == "UNEXPECTED_SUCCESS", (
        f"the role's own allow policy grants kinesisvideo:GetMedia, so the real call must "
        f"succeed before any deny is attached; got {before!r}"
    )

    # Break exactly one thing: attach an explicit deny for the same action on the same role.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=deny_policy_name,
        PolicyDocument=json.dumps(deny_policy),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, deny_policy_name))

    denied = _poll_until(
        lambda: _get_media_error(restricted_media, stream["name"]),
        lambda c: c["Code"] == "AccessDeniedException",
        timeout_s=90.0, interval_s=3.0,
    )
    assert denied["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException once the explicit deny is attached to the same role "
        f"that just succeeded, got {denied!r}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: kinesisvideo:GetMedia on resource: {stream['name']}"
    )
    assert denied["Message"] == expected, f"expected message {expected!r}, got {denied!r}"

    # No restore leg: removing this role's explicit deny for kinesisvideo:GetMedia does not
    # reliably restore access within 5 minutes even with a brand-new client and credentials,
    # unlike the grant and the deny, which each take effect within about 90 s. A restore poll
    # would only flake, so the deny is treated as one-way within this check's budget.

    control_resp = admin_media.get_media(
        StreamName=stream["name"],
        StartSelector={"StartSelectorType": "EARLIEST"},
    )
    assert control_resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    control_resp["Payload"].close()


def _get_media_error(client, stream_name):
    """The error, or the sentinel code "UNEXPECTED_SUCCESS" -- never a falsy value that could
    be mistaken for "not yet denied" while polling toward either outcome."""
    try:
        resp = client.get_media(
            StreamName=stream_name,
            StartSelector={"StartSelectorType": "EARLIEST"},
        )
    except ClientError as exc:
        return exc.response["Error"]
    resp["Payload"].close()
    return {"Code": "UNEXPECTED_SUCCESS"}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_for_assumable_role(sts, role_arn, session_name, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as exc:
            last_error = exc
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"role {role_arn} never became assumable within {timeout_s}s: {last_error}")


def _delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_active_stream(ctx):
    control = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-behav-kvm-")
    stream_arn = control.create_stream(StreamName=name, DataRetentionInHours=1)["StreamARN"]

    def _cleanup():
        try:
            control.delete_stream(StreamARN=stream_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(
        lambda: control.describe_stream(StreamName=name)["StreamInfo"]["Status"],
        lambda status: status == "ACTIVE",
    )
    return {"name": name, "arn": stream_arn}


def _media_client_for(ctx, stream_name=None, stream_arn=None, api_name="GET_MEDIA"):
    control = ctx.client("kinesisvideo")
    kwargs = {"APIName": api_name}
    if stream_arn:
        kwargs["StreamARN"] = stream_arn
    else:
        kwargs["StreamName"] = stream_name
    endpoint = control.get_data_endpoint(**kwargs)["DataEndpoint"]
    return ctx.client(
        "kinesis-video-media", endpoint_url=ctx.endpoint_url(endpoint), config=_MEDIA_CONFIG
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
