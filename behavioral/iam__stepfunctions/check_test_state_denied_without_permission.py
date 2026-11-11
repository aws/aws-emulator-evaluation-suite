"""test-state-denied-without-permission."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-denied-without-permission"
GROUP = "auth_enforcement"
SERVICES = ["iam", "stepfunctions"]

_RES_TAGS = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_PASS_DEFINITION = json.dumps({"Type": "Pass", "Result": {"ok": True}, "End": True})


def _purge_user(iam, user):
    for fn in (
        lambda: [iam.delete_user_policy(UserName=user, PolicyName=p)
                 for p in iam.list_user_policies(UserName=user)["PolicyNames"]],
        lambda: [iam.delete_access_key(UserName=user, AccessKeyId=k["AccessKeyId"])
                 for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]],
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_user(UserName=user)


def _mint_user(ctx, iam, prefix, policy_document):
    """A fresh IAM user carrying `policy_document` inline, with one access key; returns (arn, sfn client as it)."""
    name = ctx.unique_name(prefix)
    arn = iam.create_user(UserName=name, Tags=_RES_TAGS)["User"]["Arn"]
    ctx.on_cleanup(lambda: _purge_user(iam, name))
    iam.put_user_policy(UserName=name, PolicyName="inline", PolicyDocument=policy_document)
    key = iam.create_access_key(UserName=name)["AccessKey"]
    client = ctx.client("stepfunctions", creds={
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
        "aws_session_token": None,
    })
    return arn, client


def _create_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-iamsfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_SFN_TRUST_POLICY, Tags=_RES_TAGS,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _denied(user_arn, action, resource=None):
    tail = f" on resource: {resource}" if resource else ""
    return (
        "AccessDeniedException",
        f"User: {user_arn} is not authorized to perform: {action}{tail} because no "
        f"identity-based policy allows the {action} action",
    )


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _settle(probe, want, *, description, streak=3, timeout_s=120, interval_s=2):
    """Poll until probe() returns `want` on `streak` consecutive calls (IAM is eventually consistent)."""
    deadline = time.monotonic() + timeout_s
    seen, run = [], 0
    while True:
        got = probe()
        seen.append(got)
        run = run + 1 if got == want else 0
        if run >= streak:
            return seen
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description}: wanted {want!r} {streak}x in a row within {timeout_s}s; last {seen[-12:]!r}"
            )
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestState is refused with exactly AccessDeniedException when the caller lacks
    states:TestState, and separately when it lacks iam:PassRole for the roleArn it names;
    a caller holding both permissions succeeds on the identical call."""
    iam = ctx.client("iam")
    role_arn = _create_role(ctx, iam)

    full_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["states:TestState", "iam:PassRole"], "Resource": "*"}],
    })
    no_teststate_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}],
    })
    no_passrole_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:TestState", "Resource": "*"}],
    })

    full_arn, full_client = _mint_user(ctx, iam, "sim2real-iamsfn-full-", full_policy)
    denied_action_arn, denied_action_client = _mint_user(
        ctx, iam, "sim2real-iamsfn-noact-", no_teststate_policy
    )
    denied_role_arn, denied_role_client = _mint_user(
        ctx, iam, "sim2real-iamsfn-norole-", no_passrole_policy
    )

    def outcome(client, **kwargs):
        try:
            client.test_state(definition=_PASS_DEFINITION, input="{}", **kwargs)
            return "OK"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # Positive control: full permissions succeed, settled past new-key/policy propagation.
    _settle(lambda: outcome(full_client, roleArn=role_arn), "OK",
            description="TestState with states:TestState and iam:PassRole granted")

    _settle(lambda: outcome(denied_action_client), "AccessDeniedException",
            description="TestState without states:TestState permission")
    refused = _error(lambda: denied_action_client.test_state(definition=_PASS_DEFINITION, input="{}"))
    expected_denied = _denied(
        denied_action_arn, "states:TestState", f"arn:aws:states:{ctx.region}:{ctx.account}:*:*"
    )
    assert refused == expected_denied, f"expected {expected_denied!r}, got {refused!r}"

    _settle(lambda: outcome(denied_role_client, roleArn=role_arn), "AccessDeniedException",
            description="TestState without iam:PassRole permission")
    refused_role = _error(
        lambda: denied_role_client.test_state(definition=_PASS_DEFINITION, roleArn=role_arn, input="{}")
    )
    assert refused_role == _denied(denied_role_arn, "iam:PassRole", role_arn), (
        f"expected {_denied(denied_role_arn, 'iam:PassRole', role_arn)!r}, got {refused_role!r}"
    )

    # The one variable really is the permission: the same caller's role-less call works fine.
    unrelated = denied_role_client.test_state(definition=_PASS_DEFINITION, input="{}")
    assert unrelated["status"] == "SUCCEEDED", (
        f"a TestState call naming no roleArn needs no iam:PassRole: {unrelated!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
