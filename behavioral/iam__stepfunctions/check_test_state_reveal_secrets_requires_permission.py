"""test-state-reveal-secrets-requires-permission."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-state-reveal-secrets-requires-permission"
GROUP = "auth_enforcement"
SERVICES = ["iam", "stepfunctions"]

_RES_TAGS = [{"Key": "sim2real", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

_PASS_DEFINITION = '{"Type": "Pass", "Result": {"ok": true}, "End": true}'

_NO_REVEAL_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "states:TestState", '
    '"Resource": "*"}]}'
)
_WITH_REVEAL_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["states:TestState", '
    '"states:RevealSecrets"], "Resource": "*"}]}'
)


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


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message"))
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _settle(probe, want, *, description, streak=3, timeout_s=120, interval_s=2):
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
    """TestState with revealSecrets=true is refused with exactly AccessDeniedException for a
    caller that lacks states:RevealSecrets, while the identical call with revealSecrets left at
    its false default succeeds for that same caller."""
    iam = ctx.client("iam")
    no_reveal_arn, no_reveal_client = _mint_user(ctx, iam, "sim2real-iamsfn-noreveal-", _NO_REVEAL_POLICY)
    with_reveal_arn, with_reveal_client = _mint_user(
        ctx, iam, "sim2real-iamsfn-reveal-", _WITH_REVEAL_POLICY
    )

    def outcome(client, **kwargs):
        try:
            client.test_state(definition=_PASS_DEFINITION, input="{}", **kwargs)
            return "OK"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # Settle both callers' new keys/policies past IAM propagation before asserting anything.
    _settle(lambda: outcome(no_reveal_client), "OK",
            description="states:TestState alone, no revealSecrets requested")
    _settle(lambda: outcome(with_reveal_client, revealSecrets=True), "OK",
            description="states:TestState plus states:RevealSecrets, revealSecrets requested")

    # The negative: the same no-reveal caller asking for revealSecrets=true is refused.
    _settle(lambda: outcome(no_reveal_client, revealSecrets=True), "AccessDeniedException",
            description="revealSecrets=true without states:RevealSecrets")
    refused = _error(
        lambda: no_reveal_client.test_state(definition=_PASS_DEFINITION, input="{}", revealSecrets=True)
    )
    expected = (
        "AccessDeniedException",
        f"User: {no_reveal_arn} is not authorized to perform: states:RevealSecrets on resource: "
        f"arn:aws:states:{ctx.region}:{ctx.account}:*:* because no identity-based policy allows "
        "the states:RevealSecrets action",
    )
    assert refused == expected, f"expected {expected!r}, got {refused!r}"

    # Positive control: the same caller, without revealSecrets, still succeeds -- the one
    # variable is the flag, not the caller or the definition.
    plain = no_reveal_client.test_state(definition=_PASS_DEFINITION, input="{}")
    assert plain["status"] == "SUCCEEDED", f"expected SUCCEEDED without revealSecrets: {plain!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
