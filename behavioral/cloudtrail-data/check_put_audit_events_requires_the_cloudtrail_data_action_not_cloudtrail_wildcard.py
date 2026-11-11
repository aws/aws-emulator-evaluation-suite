"""put-audit-events-requires-the-cloudtrail-data-action-not-cloudtrail-wildcard."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-requires-the-cloudtrail-data-action-not-cloudtrail-wildcard"
GROUP = "audit-event-ingestion"
SERVICES = ["cloudtrail-data"]

_SESSION_NAME = "sim2real-behav-ctdprefix"
_POLICY_NAME = "sim2real-behav-ctd-action-under-test"
# Per-arm budget for IAM propagation, which is eventually consistent with nothing to poll.
_ARM_BUDGET_S = 90.0
_ASSUME_ROLE_S = 90.0


# The one permission every arm keeps, so the session is always able to prove it is alive and the
# refusals below are about PutAuditEvents rather than about a dead credential.
_BASELINE_STATEMENT = {
    "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*",
}


def _policy(*extra_statements):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [_BASELINE_STATEMENT, *extra_statements],
    })


def _audit_event():
    """A minimally valid AuditEvent. The payload is held BYTE-IDENTICAL across every arm so the
    only thing that varies between a 403 and a 400 is the caller's policy."""
    return {
        "id": str(uuid.uuid4()),
        "eventData": json.dumps({
            "version": "1.0",
            "userIdentity": {"type": "CustomIdentity", "principalId": "sim2real-behav"},
            "eventSource": "sim2real.behavioral",
            "eventName": "Sim2RealProbeEvent",
            "eventTime": "2026-01-01T00:00:00Z",
            "UID": str(uuid.uuid4()),
        }),
    }


def _error(fn):
    """(Code, Message, HTTP status) for the ClientError fn() raises; raise on unexpected success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (
            err.get("Code"),
            err.get("Message") or "",
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        )
    raise AssertionError(
        "PutAuditEvents unexpectedly SUCCEEDED; real AWS answers either AccessDeniedException "
        "(the principal may not call it) or ChannelNotFound (it may, but the channel is absent)"
    )


def _wait_for_code(fn, expected, *, timeout_s, what):
    """Poll fn() until it raises `expected` (IAM is eventually consistent); returns (code,
    message, status) and raises on the deadline rather than returning a stale verdict.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] == expected:
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"{what}: PutAuditEvents never answered {expected!r} within {timeout_s}s of the policy "
        f"change; the last answer was {last!r}. IAM is eventually consistent, so this is either "
        f"a propagation window longer than the budget (raise it) or the target evaluating the "
        f"policy differently from real AWS"
    )


def _delete_role_completely(iam, role_name):
    """Idempotent teardown for exactly the role this check created -- never a prefix sweep."""
    try:
        names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return
        raise
    for name in names:
        iam.delete_role_policy(RoleName=role_name, PolicyName=name)
    iam.delete_role(RoleName=role_name)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents is authorized under `cloudtrail-data:`: with that action the call reaches
    ChannelNotFound (400), while `cloudtrail:*` or `cloudtrail:PutAuditEvents` on the same session
    gets AccessDeniedException (403) and ingests nothing.

    Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awscloudtraildata.html
    """
    ctd = ctx.client("cloudtrail-data")
    ct = ctx.client("cloudtrail")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-ctdprefix-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav cloudtrail-data action-prefix authorization scenario",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role_completely(iam, role_name))

    allow_ctd = {
        "Effect": "Allow", "Action": "cloudtrail-data:PutAuditEvents", "Resource": "*",
    }
    allow_ct_wildcard = {"Effect": "Allow", "Action": "cloudtrail:*", "Resource": "*"}
    allow_wrong_prefix = {
        "Effect": "Allow", "Action": "cloudtrail:PutAuditEvents", "Resource": "*",
    }

    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME, PolicyDocument=_policy(allow_ctd)
    )

    # A freshly created role is eventually consistent and exposes no condition to poll, so
    # AssumeRole is a bounded retry that RAISES on expiry rather than a sleep.
    creds = None
    last_assume = None
    deadline = time.monotonic() + _ASSUME_ROLE_S
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName=_SESSION_NAME,
            )["Credentials"]
            break
        except ClientError as exc:
            last_assume = exc
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly created role {role_name!r} never succeeded within "
        f"{_ASSUME_ROLE_S}s, so there is no principal to vary: {last_assume!r}"
    )
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME}"
    limited = ctx.client("cloudtrail-data", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    limited_sts = ctx.client("sts", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })

    # Everything below reuses these two, so nothing but the policy varies between arms.
    channel_id = str(uuid.uuid4())
    channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account}:channel/{channel_id}"
    batch = [_audit_event()]

    def _call():
        return limited.put_audit_events(channelArn=channel_arn, auditEvents=batch)

    # --- Arm 0: the ARN and the payload are themselves acceptable. The caller's own principal,
    # which is fully entitled, gets the resolution error for this exact request -- so every 403 below is
    # attributable to the policy under test and not to a malformed ARN or a bad batch.
    baseline_code, baseline_message, baseline_status = _error(
        lambda: ctd.put_audit_events(channelArn=channel_arn, auditEvents=batch)
    )
    assert baseline_code == "ChannelNotFound", (
        f"arm 0: the fully entitled runner principal answered {baseline_code!r} "
        f"({baseline_message!r}) for channel {channel_arn!r}; expected ChannelNotFound. If the ARN "
        f"or the batch were themselves invalid, the 403s below would prove nothing about the policy"
    )
    assert baseline_status == 400, (
        f"arm 0: the runner principal's answer came back as HTTP {baseline_status!r} with "
        f"{baseline_code!r}; expected 400"
    )
    assert baseline_message == f"The channel {channel_arn} could not be found.", (
        f"arm 0: expected the channel-not-found message naming {channel_arn!r}, got {baseline_message!r}"
    )

    # --- Arm 1: the positive control. Authorized, so the refusal comes from resolution.
    code, message, status = _wait_for_code(
        _call, "ChannelNotFound", timeout_s=_ARM_BUDGET_S,
        what="arm 1 (cloudtrail-data:PutAuditEvents granted)",
    )
    assert status == 400, (
        f"arm 1: an AUTHORIZED call against an absent in-account channel answered HTTP {status!r} "
        f"with {code!r} ({message!r}); expected 400. The 400-vs-403 split is the discriminator "
        f"every later arm is measured against"
    )
    assert message == f"The channel {channel_arn} could not be found.", (
        f"arm 1: the resolution failure does not name the channel it could not find: {message!r}"
    )

    # --- Arm 2: break exactly one thing -- the action's SERVICE PREFIX.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME,
        PolicyDocument=_policy(allow_ct_wildcard),
    )
    code, message, status = _wait_for_code(
        _call, "AccessDeniedException", timeout_s=_ARM_BUDGET_S,
        what="arm 2 (only cloudtrail:* granted)",
    )
    assert status == 403, (
        f"arm 2: a principal holding only cloudtrail:* answered HTTP {status!r} with {code!r} "
        f"({message!r}); expected 403. PutAuditEvents lives in the cloudtrail-data: action "
        f"namespace, which cloudtrail:* does not cover (H1)"
    )
    assert message == (
        f"User: {session_arn} is not authorized to perform: cloudtrail-data:PutAuditEvents on "
        f"resource: {channel_arn} because no identity-based policy allows the "
        f"cloudtrail-data:PutAuditEvents action"
    ), f"arm 2: unexpected denial message {message!r}"
    assert "cloudtrail-data:PutAuditEvents" in message, (
        f"arm 2: the denial does not name the action it refused as "
        f"cloudtrail-data:PutAuditEvents: {message!r}. A target that reports it as "
        f"cloudtrail:PutAuditEvents has the prefix wrong, and every least-privilege policy "
        f"written against that message would be wrong too"
    )
    assert session_arn in message, (
        f"arm 2: the denial does not name the principal it refused ({session_arn!r}): {message!r}"
    )
    # The session itself is healthy -- the refusal is about this action, not about the credential.
    identity = limited_sts.get_caller_identity()
    assert identity["Arn"] == session_arn, (
        f"arm 2: sts:GetCallerIdentity from the limited session reports Arn {identity['Arn']!r}, "
        f"expected {session_arn!r}. If the session were broken the 403 above would prove nothing"
    )

    # --- Arm 3: effect absent, by an independent read at the control plane.
    try:
        _call()
        raise AssertionError(
            "arm 3: PutAuditEvents SUCCEEDED for a principal holding only cloudtrail:*"
        )
    except ClientError as exc:
        denied_response = exc.response
    assert "successful" not in denied_response, (
        f"arm 3: the denied response carries a `successful` member "
        f"{denied_response.get('successful')!r}; a refused call ingested nothing, so there is no "
        f"per-event result to report (H6)"
    )
    assert "failed" not in denied_response, (
        f"arm 3: the denied response carries a `failed` member "
        f"{denied_response.get('failed')!r}; a call refused at the authorization boundary never "
        f"reached per-event processing (H6)"
    )
    listed = ct.list_channels()
    matching = [c for c in listed.get("Channels", []) if channel_id in c.get("ChannelArn", "")]
    assert matching == [], (
        f"arm 3: ListChannels at the CloudTrail control plane reports {matching!r} for the "
        f"channel id under test ({channel_id!r}); a refused PutAuditEvents must not create the "
        f"channel it was addressed to"
    )

    # --- Arm 4: the right action name under the wrong service prefix is still a denial.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME,
        PolicyDocument=_policy(allow_wrong_prefix),
    )
    code, message, status = _wait_for_code(
        _call, "AccessDeniedException", timeout_s=_ARM_BUDGET_S,
        what="arm 4 (only cloudtrail:PutAuditEvents granted)",
    )
    assert status == 403, (
        f"arm 4: a principal granted cloudtrail:PutAuditEvents -- the right action name under "
        f"the WRONG service prefix -- answered HTTP {status!r} with {code!r} ({message!r}); "
        f"expected 403. An authorizer that matches on the operation name and ignores the prefix "
        f"lets this through (H4)"
    )
    assert "cloudtrail-data:PutAuditEvents" in message, (
        f"arm 4: the denial does not name cloudtrail-data:PutAuditEvents: {message!r}"
    )

    # --- Arm 5: restore, and the IDENTICAL call returns to the arm-1 answer.
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_POLICY_NAME, PolicyDocument=_policy(allow_ctd)
    )
    code, message, status = _wait_for_code(
        _call, "ChannelNotFound", timeout_s=_ARM_BUDGET_S,
        what="arm 5 (cloudtrail-data:PutAuditEvents restored)",
    )
    assert status == 400, (
        f"arm 5: after restoring cloudtrail-data:PutAuditEvents the identical call answered HTTP "
        f"{status!r} with {code!r} ({message!r}); expected 400/ChannelNotFound, exactly as in "
        f"arm 1. Without this beat a target that denies everything scores green on arms 2 and 4"
    )
    assert channel_arn in message, (
        f"arm 5: the restored call's resolution failure does not name the channel: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
