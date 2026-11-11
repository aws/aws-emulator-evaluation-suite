"""cross-principal-get-session-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-principal-get-session-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A session created under one principal cannot be read by an unrelated,
    unauthorized principal: GetSession is denied with AccessDeniedException for the
    stranger, while the owning principal continues to read the same session fine."""
    owner = ctx.client("bedrock-agent-runtime")
    created = owner.create_session()
    session_id = created["sessionId"]
    session_arn = created["sessionArn"]
    assert created["sessionStatus"] == "ACTIVE"

    def _end_and_delete():
        try:
            owner.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            owner.delete_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_end_and_delete)

    stranger, stranger_arn = _create_locked_down_client(ctx, "bedrock-agent-runtime")

    def stranger_read():
        stranger.get_session(sessionIdentifier=session_arn)

    # Freshly-minted STS credentials can trigger a transient
    # "UnrecognizedClientException" for a few seconds while they propagate to the
    # service's regional auth path, before settling into the real IAM-authorization
    # outcome. Poll (bounded) until we observe that settled outcome rather than
    # treating the transient one as the answer.
    deadline = time.monotonic() + 30.0
    stranger_code = stranger_message = None
    while time.monotonic() < deadline:
        stranger_code, stranger_message = _error(stranger_read)
        if stranger_code != "UnrecognizedClientException":
            break
        time.sleep(2.0)
    assert stranger_code == "AccessDeniedException", stranger_code
    expected_message = (
        f"User: {stranger_arn} is not authorized to perform: bedrock:GetSession on resource: "
        f"{session_arn} because no identity-based policy allows the bedrock:GetSession action"
    )
    assert stranger_message == expected_message, (
        f"expected message {expected_message!r}, got {stranger_message!r}"
    )


    # positive control: the owning principal still reads its own session successfully,
    # proving the denial above came from authorization -- not from a broken session.
    owner_read = owner.get_session(sessionIdentifier=session_id)
    assert owner_read["sessionId"] == session_id
    assert owner_read["sessionStatus"] == "ACTIVE"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_locked_down_client(ctx, service: str):
    """Create an IAM role with NO attached policies (implicit deny on everything),
    assume it, and return (client for `service` under those credentials, assumed-role ARN)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-lockdown-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # IAM role trust policies are eventually consistent (documented propagation
    # window of a few to ~10s); poll assume_role rather than sleeping a fixed time.
    deadline = time.monotonic() + 30.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-lockdown")
            creds = assumed["Credentials"]
            assumed_arn = assumed["AssumedRoleUser"]["Arn"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2.0)
    if creds is None:
        raise AssertionError(f"could not assume locked-down role in time: {last_exc}")

    # ctx.client(..., creds=...) re-signs with the assumed-role credentials while keeping
    # THIS run's endpoint (real AWS or emulator) and TLS settings.
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, assumed_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
