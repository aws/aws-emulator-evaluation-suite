"""version-stage-condition-key-scopes-a-read-to-one-staging-label."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# A request without VersionStage is deliberately not probed: whether AWSCURRENT is synthesised
# into the condition context for it is not asserted here.

CHECK = "version-stage-condition-key-scopes-a-read-to-one-staging-label"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_POLICY_NAME = "sim2real-behav-smstage-read"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A GetSecretValue grant conditioned on secretsmanager:VersionStage admits the AWSCURRENT read,
    refuses the same read of AWSPENDING with AccessDeniedException, and admits it once widened.

    Reference: https://docs.aws.amazon.com/service-authorization/latest/reference/list_secretsmanager.html
    """
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-smstagecond-")
    created = sm.create_secret(
        Name=name,
        SecretString="current-credential",
        Description="sim2real behavioral draft: secretsmanager:VersionStage condition key",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    pending_version = sm.put_secret_value(
        SecretId=arn, SecretString="pending-credential", VersionStages=["AWSPENDING"]
    )["VersionId"]
    stages = _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        lambda m: "AWSPENDING" in m.get(pending_version, []),
        timeout_s=60.0,
        interval_s=2.0,
        description="the AWSPENDING label to appear on the second version",
    )
    current_holders = [v for v, s in stages.items() if "AWSCURRENT" in s]
    assert len(current_holders) == 1 and current_holders[0] != pending_version, (
        f"exactly one version other than the pending one must hold AWSCURRENT; the index is "
        f"{stages!r}"
    )

    # Both labels are readable unscoped, so a later refusal cannot be a missing version.
    unscoped_current = sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")["SecretString"]
    assert unscoped_current == "current-credential", (
        f"the harness's own AWSCURRENT read must serve 'current-credential'; got "
        f"{unscoped_current!r}"
    )
    unscoped_pending = sm.get_secret_value(SecretId=arn, VersionStage="AWSPENDING")["SecretString"]
    assert unscoped_pending == "pending-credential", (
        f"the harness's own AWSPENDING read must serve 'pending-credential'; without this control "
        f"the role's refusal below would be indistinguishable from an absent version; got "
        f"{unscoped_pending!r}"
    )

    # A role whose only secretsmanager grant is stage-conditioned.
    role_name = ctx.unique_name("sim2real-behav-smstagerole-")
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
    _put_stage_policy(iam, role_name, arn, ["AWSCURRENT"])
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME))

    creds = _assume(sts, role_arn, "sim2real-behav-smstage")
    as_role_sts = ctx.client("sts", creds=_session_creds(creds))
    who = as_role_sts.get_caller_identity()["Arn"]
    assert who.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role_name}/"), (
        f"the probed calls must be signed by the condition-scoped role, not by the harness "
        f"identity; GetCallerIdentity returned {who!r}"
    )
    as_role = ctx.client("secretsmanager", creds=_session_creds(creds))

    # A rewritten inline policy can take longer to become effective than a first write; 120s bound.
    permitted = _poll(
        lambda: _probe(as_role, arn, "AWSCURRENT"),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            "the role's stage-conditioned inline grant to become effective for AWSCURRENT "
            "(IAM exposes no API reporting an inline policy as effective, so the bounded "
            "AccessDeniedException retry IS the wait)"
        ),
    )
    assert permitted[1] == "current-credential", (
        f"the role's grant names AWSCURRENT, so its AWSCURRENT read must serve "
        f"'current-credential'; got {permitted[1]!r}"
    )

    refused = _probe(as_role, arn, "AWSPENDING")
    assert refused[0] == "AccessDeniedException", (
        f"the role's grant is conditioned on secretsmanager:VersionStage == AWSCURRENT, so the "
        f"SAME principal, action and resource with VersionStage=AWSPENDING must be refused with "
        f"AccessDeniedException; got {refused[0]!r} (payload {refused[1]!r})"
    )
    expected_refusal = (
        f"User: {who} is not authorized to perform: secretsmanager:GetSecretValue on resource: "
        f"{arn} because no identity-based policy allows the secretsmanager:GetSecretValue action"
    )
    assert refused[2] == expected_refusal, (
        f"refusal message {refused[2]!r}, expected {expected_refusal!r}"
    )

    assert refused[1] is None, (
        f"a refused GetSecretValue must deliver no secret material; the probe captured "
        f"{refused[1]!r}"
    )
    unchanged = sm.describe_secret(SecretId=arn)["VersionIdsToStages"]
    assert unchanged == stages, (
        f"a refused read must not touch the staging index; before {stages!r}, after {unchanged!r}"
    )
    still_ok = _probe(as_role, arn, "AWSCURRENT")
    assert still_ok[0] == "OK" and still_ok[1] == "current-credential", (
        f"the refusal must be scoped to the staging label, not a blanket lockout; the role's "
        f"AWSCURRENT read returned {still_ok!r}"
    )

    _put_stage_policy(iam, role_name, arn, ["AWSCURRENT", "AWSPENDING"])
    widened = _poll(
        lambda: _probe(as_role, arn, "AWSPENDING"),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description="the widened stage condition to admit the previously refused AWSPENDING read",
    )
    assert widened[1] == "pending-credential", (
        f"once the condition admits AWSPENDING the identical call must serve the pending bytes; "
        f"expected 'pending-credential', got {widened[1]!r}"
    )
    final = _probe(as_role, arn, "AWSCURRENT")
    assert final[0] == "OK" and final[1] == "current-credential", (
        f"widening the condition must not disturb the AWSCURRENT grant; got {final!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _put_stage_policy(iam, role_name: str, secret_arn: str, allowed_stages: list[str]) -> None:
    """GetSecretValue on one ARN, conditioned on the requested staging label.
    ForAnyValue because the condition key is multi-valued."""
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
                "Condition": {
                    "ForAnyValue:StringEquals": {"secretsmanager:VersionStage": allowed_stages}
                },
            }],
        }),
    )


def _probe(client, secret_id: str, stage: str):
    """(code_or_'OK', secret_string_or_None, message_or_None) for one GetSecretValue call."""
    try:
        resp = client.get_secret_value(SecretId=secret_id, VersionStage=stage)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), None, err.get("Message")
    return "OK", resp.get("SecretString"), None


def _assume(sts, role_arn: str, session_name: str, *, timeout_s=120.0, interval_s=3.0):
    """AssumeRole, retried while a new role's trust policy propagates; raises at the deadline."""
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


def _session_creds(creds) -> dict[str, str]:
    """The assumed-role session as a ``ctx.client`` creds override."""
    return {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll that raises on timeout."""
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
