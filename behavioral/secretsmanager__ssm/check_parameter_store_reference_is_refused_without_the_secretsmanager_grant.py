"""parameter-store-reference-is-refused-without-the-secretsmanager-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-store-reference-is-refused-without-the-secretsmanager-grant"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager", "ssm"]

_PREFIX = "/aws/reference/secretsmanager"
_POLICY_NAME = "sim2real-behav-smssmref-grant"
# SSM wraps the failed downstream Secrets Manager call in its own generic ValidationException,
# rather than surfacing AccessDeniedException or masking it as ParameterNotFound.
_REFUSAL_CODE = "ValidationException"


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A principal with ssm:GetParameter but no secretsmanager:GetSecretValue is refused a
    /aws/reference/secretsmanager read, reads ordinary parameters fine, and succeeds once granted.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/integration-ps-secretsmanager.html
    """
    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-smssmauth-")
    arn = sm.create_secret(
        Name=name,
        SecretString="reference-guarded-value",
        Description="sim2real behavioral draft: reference-path authorization",
        Tags=_sim2real_tags(),
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    ref = f"{_PREFIX}/{name}"

    control_param = "/" + ctx.unique_name("sim2real-behav-smssmauth-plain-")
    ssm.put_parameter(
        Name=control_param,
        Value="ordinary-parameter-value",
        Type="String",
        Tags=_sim2real_tags(),
    )
    ctx.on_cleanup(lambda: _delete_parameter(ssm, control_param))

    # The reference resolves for an unrestricted principal. Established BEFORE the role exists, so a
    # later refusal cannot be "the reference path does not work here".
    baseline = _poll(
        lambda: _get_parameter(ssm, ref),
        lambda r: r[0] == "OK",
        timeout_s=90.0,
        interval_s=3.0,
        description=(
            f"the reference {ref!r} to resolve for the harness's own credentials (the front door is "
            f"a different service from the store and may lag CreateSecret)"
        ),
    )
    assert baseline[1]["Value"] == "reference-guarded-value", (
        f"the harness's own reference read must serve the secret's bytes before the role is graded; "
        f"got {baseline[1].get('Value')!r}"
    )

    # The role holds DescribeSecret throughout, so "some" Secrets Manager permission is not enough.
    role_name = ctx.unique_name("sim2real-behav-smssmrole-")
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
    _put_policy(iam, role_name, secret_arn=arn, grant_secret_value=False)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_POLICY_NAME))

    creds = _assume(sts, role_arn, "sim2real-behav-smssmauth")
    who = _client_for_session(ctx, creds, "sts").get_caller_identity()["Arn"]
    assert who.startswith(f"arn:aws:sts::{account_id}:assumed-role/{role_name}/"), (
        f"the probed reads must be signed by the restricted role, not the harness identity; "
        f"GetCallerIdentity returned {who!r}"
    )
    as_role_ssm = _client_for_session(ctx, creds, "ssm")
    as_role_sm = _client_for_session(ctx, creds, "secretsmanager")

    # Positive control: the role's ssm:GetParameter genuinely works.
    plain = _poll(
        lambda: _get_parameter(as_role_ssm, control_param),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            "the role's ssm:GetParameter grant to become effective on an ordinary parameter (IAM "
            "reports no inline policy as effective, so the bounded retry IS the wait)"
        ),
    )
    assert plain[1]["Value"] == "ordinary-parameter-value", (
        f"the role must read an ordinary parameter successfully, or its refusal on the reference "
        f"path proves nothing; got {plain[1].get('Value')!r}"
    )
    described = as_role_sm.describe_secret(SecretId=arn)
    assert described["ARN"] == arn, (
        f"the role holds secretsmanager:DescribeSecret and must be able to use it, so the refusal "
        f"below is specifically about the VALUE grant; DescribeSecret returned {described!r}"
    )

    refused_code, refused_value, refused_message = _get_parameter_with_message(as_role_ssm, ref)
    assert refused_value is None, (
        f"a principal without secretsmanager:GetSecretValue must receive NO secret material through "
        f"the Parameter Store reference path; the probe captured {refused_value!r}"
    )
    # The message is what separates the dependency-failure wrapper from an ordinary
    # malformed-name ValidationException.
    assert refused_code == _REFUSAL_CODE, (
        f"the reference read must be refused with {_REFUSAL_CODE!r} (SSM's wrapper for a failed "
        f"downstream Secrets Manager call); got {refused_code!r}"
    )
    assert refused_message == "An error occurred while calling one AWS dependency service.", (
        f"expected the exact ValidationException message AWS returns, got {refused_message!r}"
    )
    assert "dependency service" in (refused_message or ""), (
        f"the refusal must be SSM's dependency-failure wrapper, not an ordinary request-validation "
        f"ValidationException, or this assertion cannot separate the two; got message "
        f"{refused_message!r}"
    )
    # The direct refusal attributes the front-door refusal to Secrets Manager's decision.
    direct, direct_message = _error_code(lambda: as_role_sm.get_secret_value(SecretId=arn))
    assert direct == "AccessDeniedException", (
        f"the role must be refused the direct GetSecretValue with AccessDeniedException, which is "
        f"the decision the reference path is supposed to honour; got {direct!r}"
    )
    assert direct_message == f"User: {who} is not authorized to perform: secretsmanager:GetSecretValue on resource: {described['ARN']} because no identity-based policy allows the secretsmanager:GetSecretValue action", (
        f"expected the exact AccessDeniedException message AWS returns, got {direct_message!r}"
    )

    assert sm.get_secret_value(SecretId=arn)["SecretString"] == "reference-guarded-value", (
        "the refusals must leave the secret readable to the harness's own credentials"
    )
    assert "DeletedDate" not in sm.describe_secret(SecretId=arn), (
        "a refused read must not disturb the secret's lifecycle state"
    )

    _put_policy(iam, role_name, secret_arn=arn, grant_secret_value=True)
    granted = _poll(
        lambda: _get_parameter(as_role_ssm, ref),
        lambda r: r[0] == "OK",
        timeout_s=120.0,
        interval_s=3.0,
        description=(
            "the added secretsmanager:GetSecretValue grant to make the previously refused reference "
            "read succeed"
        ),
    )
    assert granted[1]["Value"] == "reference-guarded-value", (
        f"once the Secrets Manager action is granted, the IDENTICAL SSM read must serve the secret's "
        f"bytes; expected 'reference-guarded-value', got {granted[1].get('Value')!r}"
    )
    assert granted[1]["Name"] == ref, (
        f"the echoed parameter name must still be the reference path; got {granted[1].get('Name')!r}"
    )
    plain_again = _get_parameter(as_role_ssm, control_param)
    assert plain_again[0] == "OK" and plain_again[1]["Value"] == "ordinary-parameter-value", (
        f"widening the Secrets Manager grant must not disturb the role's ordinary parameter read; "
        f"got {plain_again!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _put_policy(iam, role_name: str, *, secret_arn: str, grant_secret_value: bool) -> None:
    """Grant ssm:GetParameter* and DescribeSecret in both arms; only GetSecretValue varies."""
    statements = [
        {
            "Sid": "AllowAllParameterReads",
            "Effect": "Allow",
            "Action": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
            "Resource": "*",
        },
        {
            "Sid": "AllowSecretMetadataOnly",
            "Effect": "Allow",
            "Action": "secretsmanager:DescribeSecret",
            "Resource": secret_arn,
        },
    ]
    if grant_secret_value:
        statements.append({
            "Sid": "AllowSecretValue",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": secret_arn,
        })
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_POLICY_NAME,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _get_parameter(ssm, name: str):
    """Return (code or 'OK', Parameter or None)."""
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=True)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), None
    return "OK", resp["Parameter"]


def _get_parameter_with_message(ssm, name: str):
    """Like `_get_parameter`, plus the error message."""
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=True)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), None, err.get("Message")
    return "OK", resp["Parameter"], None


def _delete_parameter(ssm, name: str) -> None:
    """Delete this check's own parameter, tolerating ParameterNotFound."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code != "ParameterNotFound":
            raise RuntimeError(f"delete_parameter({name}) -> {code}") from exc


def _error_code(fn):
    """Return the AWS error code and message; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _assume(sts, role_arn: str, session_name: str, *, timeout_s=120.0, interval_s=3.0):
    """AssumeRole with a bounded retry; a new role's trust policy takes time to propagate."""
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
    """A client signing AS the minted principal, against the same target as ctx.client()."""
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
