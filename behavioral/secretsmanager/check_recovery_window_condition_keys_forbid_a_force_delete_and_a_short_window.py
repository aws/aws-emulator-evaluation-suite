"""recovery-window-condition-keys-forbid-a-force-delete-and-a-short-window."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_MARKED_FOR_DELETION_MESSAGE = (
    "You can't perform this operation on the secret because it was marked for deletion."
)
CHECK = "recovery-window-condition-keys-forbid-a-force-delete-and-a-short-window"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_POLICY_NAME = "sim2real-behav-smwindow-guardrail"
_MIN_WINDOW_DAYS = 30


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """An identity policy denying DeleteSecret on the ForceDeleteWithoutRecovery and
    RecoveryWindowInDays condition keys refuses a force delete and a 7-day window with
    AccessDeniedException, while the same role's 30-day delete succeeds.

    Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html
    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html
    """
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # A fresh secret per probed delete, so no probe is confounded by an earlier one.
    forced = _make_secret(ctx, sm, "force")
    short = _make_secret(ctx, sm, "short")
    compliant = _make_secret(ctx, sm, "ok")

    # Control with unrestricted credentials: a 7-day window is a valid request, so the role's later
    # refusal of the identical shape is authorization, not input validation.
    validity = _make_secret(ctx, sm, "valid7")
    valid_resp = sm.delete_secret(SecretId=validity["arn"], RecoveryWindowInDays=7)
    assert "DeletionDate" in valid_resp, (
        f"RecoveryWindowInDays=7 is the documented minimum and must be accepted by an "
        f"unrestricted principal, returning a DeletionDate; DeleteSecret returned "
        f"{sorted(valid_resp)!r}"
    )
    sm.restore_secret(SecretId=validity["arn"])

    # Allow plus two Denies: a condition over a key absent from the request does not match, so the
    # unconditioned delete is still allowed; an Allow conditioned on an absent key would refuse all.
    role_name = ctx.unique_name("sim2real-behav-smwindowrole-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Path="/",
        Tags=_sim2real_tags(),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDeleteAndRead",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:DeleteSecret", "secretsmanager:DescribeSecret"],
                    "Resource": "*",
                },
                {
                    "Sid": "DenyIrreversibleDelete",
                    "Effect": "Deny",
                    "Action": "secretsmanager:DeleteSecret",
                    "Resource": "*",
                    "Condition": {
                        "Bool": {"secretsmanager:ForceDeleteWithoutRecovery": "true"}
                    },
                },
                {
                    "Sid": "DenyShortRecoveryWindow",
                    "Effect": "Deny",
                    "Action": "secretsmanager:DeleteSecret",
                    "Resource": "*",
                    "Condition": {
                        "NumericLessThan": {
                            "secretsmanager:RecoveryWindowInDays": str(_MIN_WINDOW_DAYS)
                        }
                    },
                },
            ],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME))

    creds = _assume(sts, role_arn, "sim2real-behav-smwindow")
    who = _client_for_session(ctx, creds, "sts").get_caller_identity()["Arn"]
    assert who.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role_name}/"), (
        f"the probed deletes must be signed by the guardrailed role, not the harness identity; "
        f"GetCallerIdentity returned {who!r}"
    )
    as_role = _client_for_session(ctx, creds, "secretsmanager")

    called_at = time.time()
    ok = _poll(
        lambda: _delete_probe(
            as_role, compliant["arn"], RecoveryWindowInDays=_MIN_WINDOW_DAYS
        ),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            "the role's Allow+Deny guardrail to become effective for a compliant 30-day delete "
            "(IAM reports no inline policy as effective, so the bounded retry IS the wait)"
        ),
    )
    assert ok[1] is not None, (
        f"the permitted delete must return a DeletionDate; the probe captured {ok[1]!r}"
    )
    # Derived from the live clock as a tolerance band: no doc pins the DeletionDate rounding.
    offset_days = (ok[1].timestamp() - called_at) / 86400.0
    assert 29.0 <= offset_days <= 31.0, (
        f"a {_MIN_WINDOW_DAYS}-day recovery window must set DeletionDate ~{_MIN_WINDOW_DAYS} days "
        f"after the call; measured {offset_days:.3f} days from the live clock reading taken "
        f"immediately before the call"
    )
    described = sm.describe_secret(SecretId=compliant["arn"])
    assert "DeletedDate" in described, (
        f"DescribeSecret must report DeletedDate for the secret the role just scheduled; it "
        f"returned {sorted(described)!r}"
    )

    force_refused = _delete_probe(as_role, forced["arn"], ForceDeleteWithoutRecovery=True)
    assert force_refused[0] == "AccessDeniedException", (
        f"the guardrail denies DeleteSecret when ForceDeleteWithoutRecovery is true, so the SAME "
        f"principal, action and resource-pattern must be refused with AccessDeniedException; got "
        f"{force_refused[0]!r}"
    )
    assert force_refused[2] == _explicit_deny_message(who, forced["arn"]), (
        f"unexpected ForceDeleteWithoutRecovery denial message: {force_refused[2]!r}"
    )
    short_refused = _delete_probe(as_role, short["arn"], RecoveryWindowInDays=7)
    assert short_refused[0] == "AccessDeniedException", (
        f"the guardrail denies a recovery window under {_MIN_WINDOW_DAYS} days, so the identical "
        f"delete with RecoveryWindowInDays=7 -- a window real AWS itself accepts, proven above -- "
        f"must be refused with AccessDeniedException; got {short_refused[0]!r}"
    )
    assert short_refused[2] == _explicit_deny_message(who, short["arn"]), (
        f"unexpected short-window denial message: {short_refused[2]!r}"
    )

    for label, subject in (("force-deleted", forced), ("short-window", short)):
        state = sm.describe_secret(SecretId=subject["arn"])
        assert "DeletedDate" not in state, (
            f"the {label} probe was refused, so DescribeSecret must report no DeletedDate for "
            f"{subject['name']}; it returned DeletedDate={state.get('DeletedDate')!r}"
        )
        served = sm.get_secret_value(SecretId=subject["arn"])["SecretString"]
        assert served == subject["value"], (
            f"the {label} probe was refused, so the secret must remain fully readable; expected "
            f"{subject['value']!r}, got {served!r}"
        )

    restored = _delete_probe(as_role, short["arn"], RecoveryWindowInDays=_MIN_WINDOW_DAYS)
    assert restored[0] == "OK", (
        f"changing only RecoveryWindowInDays from 7 to {_MIN_WINDOW_DAYS} must make the identical "
        f"delete succeed; got {restored[0]!r}"
    )
    after = sm.describe_secret(SecretId=short["arn"])
    assert "DeletedDate" in after, (
        f"the now-compliant delete must be visible as DeletedDate on an independent DescribeSecret; "
        f"it returned {sorted(after)!r}"
    )
    scheduled_code, scheduled_message = _error_code(lambda: sm.get_secret_value(SecretId=short["arn"]))
    assert scheduled_code == "InvalidRequestException", (
        f"a secret scheduled for deletion must refuse GetSecretValue with InvalidRequestException; "
        f"got {scheduled_code!r}"
    )
    assert scheduled_message == _MARKED_FOR_DELETION_MESSAGE, (
        f"unexpected scheduled-for-deletion refusal message: {scheduled_message!r}"
    )
    # Undo the scheduling so cleanup's force-delete is a plain single call on a live secret.
    sm.restore_secret(SecretId=short["arn"])
    sm.restore_secret(SecretId=compliant["arn"])


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _make_secret(ctx, sm, slug: str) -> dict:
    """Create one uniquely named subject secret and register its teardown."""
    name = ctx.unique_name(f"sim2real-behav-smwindow-{slug}-")
    value = f"credential-{slug}"
    arn = sm.create_secret(
        Name=name,
        SecretString=value,
        Description="sim2real behavioral draft: DeleteSecret request-parameter conditions",
        Tags=_sim2real_tags(),
    )["ARN"]
    ctx.on_cleanup(lambda: _reap(sm, arn))
    return {"name": name, "arn": arn, "value": value}


def _reap(sm, arn: str) -> None:
    """Force-delete, tolerating a secret already gone; a secret scheduled for deletion still
    accepts ForceDeleteWithoutRecovery."""
    try:
        sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code == "ResourceNotFoundException":
            return
        teardown_code = exc.response.get("Error", {}).get("Code", "")
        if teardown_code not in ("ResourceNotFoundException",):
            raise RuntimeError(
                f"secret {arn} not force-deleted ({code}); it bills $0.40/month until reaped"
            ) from exc


def _explicit_deny_message(caller_arn: str, secret_arn: str) -> str:
    """The DeleteSecret refusal for a request an identity-policy Deny matched."""
    return (
        f"User: {caller_arn} is not authorized to perform: secretsmanager:DeleteSecret on "
        f"resource: {secret_arn} with an explicit deny in an identity-based policy"
    )


def _delete_probe(client, secret_id: str, **kwargs):
    """(code_or_'OK', DeletionDate_or_None, message_or_None) from one DeleteSecret call."""
    try:
        resp = client.delete_secret(SecretId=secret_id, **kwargs)
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), None, error.get("Message")
    return "OK", resp.get("DeletionDate"), None


def _error_code(fn):
    """The captured AWS (error code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _assume(sts, role_arn: str, session_name: str, *, timeout_s=120.0, interval_s=3.0):
    """AssumeRole with a bounded retry: a just-created role refuses until its trust policy
    propagates, and IAM has no API reporting a trust policy as effective."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not assume {role_arn} within {timeout_s}s; last error {last!r}"
                ) from exc
            time.sleep(interval_s)


def _client_for_session(ctx, creds, service: str):
    """A client on the same target, signing AS the assumed-role session."""
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
