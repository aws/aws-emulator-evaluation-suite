"""invoke-model-missing-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-model-missing-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
_ALLOW = "sim2real-behav-bedrock-invoke-allow"


def _nova_body(text: str) -> bytes:
    return json.dumps(
        {"messages": [{"role": "user", "content": [{"text": text}]}], "inferenceConfig": {"maxTokens": 20, "temperature": 0, "topP": 1}}
    ).encode("utf-8")


def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "UNEXPECTED_SUCCESS"


def _refusal(fn):
    """(code, message) of the refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _denial(user_arn: str, region: str) -> str:
    return (
        f"User: {user_arn} is not authorized to perform: bedrock:InvokeModel on resource: "
        f"arn:aws:bedrock:{region}::foundation-model/{TEXT_MODEL} because no identity-based "
        f"policy allows the bedrock:InvokeModel action"
    )


def _client_for_credentials(ctx, access_key_id, secret_access_key, service):
    """A client signing AS the minted principal against the same target."""
    return ctx.client(
        service, creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key}
    )


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s; last observation {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _allow_policy():
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:Converse"], "Resource": "*"},
            ],
        }
    )


def _drop_allow(iam, user):
    """Delete the inline Allow policy, ignoring NoSuchEntity."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_ALLOW)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A user's signed InvokeModel/Converse succeed with an Allow, fail with the exact
    AccessDeniedException once it is deleted (simulator: implicitDeny), and succeed again when
    restored, so the refusal is caused by the missing grant."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-bedrock-user-")

    iam.create_user(UserName=user, Path="/", Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    user_arn = iam.get_user(UserName=user)["User"]["Arn"]

    iam.put_user_policy(UserName=user, PolicyName=_ALLOW, PolicyDocument=_allow_policy())
    ctx.on_cleanup(lambda: _drop_allow(iam, user))

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    as_user = _client_for_credentials(ctx, key["AccessKeyId"], key["SecretAccessKey"], "bedrock-runtime")

    def _invoke():
        resp = as_user.invoke_model(
            modelId=TEXT_MODEL, body=_nova_body("Say the word yes and nothing else."), contentType="application/json"
        )
        return json.loads(resp["body"].read())["output"]["message"]["content"][0]["text"]

    def _converse():
        resp = as_user.converse(
            modelId=TEXT_MODEL, messages=[{"role": "user", "content": [{"text": "Say the word yes and nothing else."}]}]
        )
        return resp["output"]["message"]["content"][0]["text"]

    # IAM is eventually consistent for both the new key and the grant, so each leg polls.
    before_invoke = _poll(
        lambda: _error_code(_invoke),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90,
        interval_s=3,
        description="the Allow becomes effective for bedrock:InvokeModel on a real signed call",
    )
    assert before_invoke == "UNEXPECTED_SUCCESS", (
        f"with the Allow in place the real signed InvokeModel must succeed; got {before_invoke!r} "
        "-- the control failed, so nothing below would be interpretable"
    )
    before_converse = _poll(
        lambda: _error_code(_converse),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90,
        interval_s=3,
        description="the Allow becomes effective for bedrock:Converse on a real signed call",
    )
    assert before_converse == "UNEXPECTED_SUCCESS", (
        f"with the Allow in place the real signed Converse must succeed; got {before_converse!r}"
    )

    # Delete the Allow so the permission is missing, not explicitly denied.
    _drop_allow(iam, user)

    after_invoke = _poll(
        lambda: _error_code(_invoke),
        lambda c: c == "AccessDeniedException",
        timeout_s=90,
        interval_s=3,
        description="InvokeModel is refused once the permission is missing",
    )
    assert after_invoke == "AccessDeniedException", (
        f"with no policy granting bedrock:InvokeModel, the real signed call must be refused with "
        f"exactly AccessDeniedException; got {after_invoke!r}"
    )
    after_converse = _poll(
        lambda: _error_code(_converse),
        lambda c: c == "AccessDeniedException",
        timeout_s=90,
        interval_s=3,
        description="Converse is refused once the permission is missing",
    )
    assert after_converse == "AccessDeniedException", (
        f"with no policy granting bedrock:Converse, the real signed call must be refused with "
        f"exactly AccessDeniedException; got {after_converse!r}"
    )
    expected_denial = _denial(user_arn, ctx.region)
    invoke_code, invoke_message = _refusal(_invoke)
    assert (invoke_code, invoke_message) == ("AccessDeniedException", expected_denial), (
        f"InvokeModel refusal: {invoke_code!r} {invoke_message!r}"
    )
    converse_code, converse_message = _refusal(_converse)
    assert (converse_code, converse_message) == ("AccessDeniedException", expected_denial), (
        f"Converse refusal: {converse_code!r} {converse_message!r}"
    )

    sim = iam.simulate_principal_policy(
        PolicySourceArn=user_arn, ActionNames=["bedrock:InvokeModel", "bedrock:Converse"]
    )
    decisions = {r["EvalActionName"]: r["EvalDecision"] for r in sim["EvaluationResults"]}
    assert decisions.get("bedrock:InvokeModel") == "implicitDeny", f"InvokeModel: {decisions}"
    assert decisions.get("bedrock:Converse") == "implicitDeny", f"Converse: {decisions}"

    iam.put_user_policy(UserName=user, PolicyName=_ALLOW, PolicyDocument=_allow_policy())
    ctx.on_cleanup(lambda: _drop_allow(iam, user))

    restored_invoke = _poll(
        lambda: _error_code(_invoke),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90,
        interval_s=3,
        description="restoring the Allow restores InvokeModel",
    )
    assert restored_invoke == "UNEXPECTED_SUCCESS", (
        f"restoring the Allow must restore the real signed InvokeModel call; got {restored_invoke!r}"
    )
    restored_converse = _poll(
        lambda: _error_code(_converse),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90,
        interval_s=3,
        description="restoring the Allow restores Converse",
    )
    assert restored_converse == "UNEXPECTED_SUCCESS", (
        f"restoring the Allow must restore the real signed Converse call; got {restored_converse!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
