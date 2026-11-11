"""bedrock-runtime-model-arn-scoped-session-denied-for-second-model."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-runtime-model-arn-scoped-session-denied-for-second-model"
GROUP = 'overly-permissive'
SERVICES = ['bedrock-runtime', 'iam', 'sts']

# Both models are invocable ON_DEMAND by bare id; models that require an inference profile would
# put a different resource type in the policy.
MODEL_A = "amazon.nova-lite-v1:0"
MODEL_B = "mistral.mistral-large-2407-v1:0"

_PROMPT = "Reply with exactly the single word PONG and nothing else."
_INFERENCE = {"maxTokens": 64, "temperature": 0.0}
# IAM has no policy-effective signal, so the allowed path is retried on AccessDenied until it works.
_PROPAGATION_TIMEOUT_S = 240.0

# AssumeRole response member -> suffix of the boto3 client keyword that carries it.
_CRED_MEMBERS = {"AccessKeyId": "access_key_id",
                 "SecretAccessKey": "secret_access_key",
                 "SessionToken": "session_token"}


def _cred_kwargs(creds):
    """The minted credentials as the ``creds`` override ``ctx.client`` signs with."""
    return {f"aws_{suffix}": creds[member] for member, suffix in _CRED_MEMBERS.items()}


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A session whose policy allows InvokeModel on model A really generates with A, while model B
    is refused with an exact AccessDeniedException; Bedrock authorises per model resource.
    The base session invoking B proves B is available, so the refusal is the policy's doing.
    """
    sts = ctx.client("sts")

    def _scoped_client(service, creds):
        # Explicit override only; os.environ would leak the session into later code in this process.
        return ctx.client(service, creds=_cred_kwargs(creds))

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code", "")
        return "NO-ERROR"

    def _poll(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed {last!r})")
            time.sleep(interval_s)

    def _model_arn(model_id):
        # Foundation-model ARNs carry no account id.
        return f"arn:aws:bedrock:{ctx.region}::foundation-model/{model_id}"

    def _converse(client, model_id):
        return client.converse(modelId=model_id,
                               messages=[{"role": "user", "content": [{"text": _PROMPT}]}],
                               inferenceConfig=_INFERENCE)

    def _text(resp):
        return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])

    def _drop_role(iam, role_name):
        # An inline policy blocks delete_role, so it goes first; then poll to actual disappearance.
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        for page in iam.get_paginator("list_attached_role_policies").paginate(
                RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
        _poll(lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=60.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    iam = ctx.client("iam")
    account = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-brt-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                           "Action": ["sts:AssumeRole"]}],
        }),
        Description="sim2real bedrock-runtime model-resource scoping",
        Tags=[{"Key": "sim2real", "Value": "model-arn-scoped-session"},
              {"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(iam, role_name))

    # The Resource element names model A and nothing else.
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                "Resource": [_model_arn(MODEL_A)],
            }],
        }),
    )

    session_name = ctx.unique_name("sim2real-behav-sess-")
    assumed = _poll(
        lambda: _try_assume(sts, role_arn, session_name),
        lambda r: isinstance(r, dict),
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=3.0,
        description=f"role {role_arn} became assumable")
    creds = assumed["Credentials"]
    scoped_rt = _scoped_client("bedrock-runtime", creds)
    scoped_sts = _scoped_client("sts", creds)

    # The scoped session really is a different principal from the one that created the role.
    scoped_identity = _poll(
        lambda: _identity_or_code(scoped_sts),
        lambda r: isinstance(r, dict), timeout_s=120.0, interval_s=2.0,
        description="the minted credentials became active")
    assert f":assumed-role/{role_name}/" in scoped_identity["Arn"], (
        f"the scoped client must be the assumed role, else the denial below belongs to another "
        f"principal; got {scoped_identity['Arn']!r}"
    )

    # Until the allowed path succeeds, an AccessDenied on model B could just be IAM propagation.
    allowed = _poll(
        lambda: _converse_or_code(scoped_rt, MODEL_A),
        lambda r: isinstance(r, dict),
        timeout_s=_PROPAGATION_TIMEOUT_S, interval_s=5.0,
        description=f"the scoped session became able to invoke {MODEL_A}")
    assert allowed["stopReason"] == "end_turn", (
        f"the permitted model must complete a real generation under the scoped credentials, not "
        f"merely avoid an error; got {allowed['stopReason']!r} text={_text(allowed)!r}"
    )
    assert "PONG" in _text(allowed).upper(), (
        f"the permitted model returned no usable generation under the scoped credentials; got "
        f"{_text(allowed)!r}"
    )
    assert allowed["usage"]["outputTokens"] > 0, (
        f"the permitted invocation billed no output tokens, so nothing was generated; usage="
        f"{allowed['usage']!r}"
    )

    # Same session, same request, a model the policy omits.
    denied = _converse_or_code(scoped_rt, MODEL_B)
    assert isinstance(denied, tuple) and denied[0] == "AccessDeniedException", (
        f"a model outside the policy's Resource list must be refused with AccessDeniedException "
        f"even though the same session may invoke {MODEL_A}; got {denied!r}"
    )
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{session_name} is not authorized "
        f"to perform: bedrock:InvokeModel on resource: {_model_arn(MODEL_B)} because no "
        f"identity-based policy allows the bedrock:InvokeModel action"
    )
    assert denied[1] == expected_message, (
        f"the refusal must name the session, the action and the omitted model ARN exactly; "
        f"expected {expected_message!r}, got {denied[1]!r}"
    )
    # Re-check model A so the denial cannot be explained by the session having expired.
    still_allowed = _converse_or_code(scoped_rt, MODEL_A)
    assert isinstance(still_allowed, dict), (
        f"the permitted model must still be invocable after the refusal, otherwise the session "
        f"simply died and the denial proves nothing; got {still_allowed!r}"
    )
    assert "PONG" in _text(still_allowed).upper(), (
        f"the re-checked barrier produced no generation; got {_text(still_allowed)!r}"
    )

    # Control: the base session can invoke model B, so the denial is not model unavailability.
    base_rt = ctx.client("bedrock-runtime")
    base_b = _converse(base_rt, MODEL_B)
    assert base_b["stopReason"] == "end_turn", (
        f"the base session must be able to invoke {MODEL_B}, else the denial above may be model "
        f"unavailability; got {base_b['stopReason']!r} text={_text(base_b)!r}"
    )
    assert "PONG" in _text(base_b).upper(), (
        f"the base session's invocation of {MODEL_B} produced no usable generation; got "
        f"{_text(base_b)!r}"
    )


def _try_assume(sts, role_arn, session_name):
    """The AssumeRole response on success, or the error code string."""
    try:
        return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")


def _identity_or_code(sts_client):
    """Caller identity or error code; GetCallerIdentity needs no permissions."""
    try:
        return sts_client.get_caller_identity()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code", "")


def _converse_or_code(rt, model_id):
    """The Converse response on success, or the error's (code, message)."""
    try:
        return rt.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [
                {"text": "Reply with exactly the single word PONG and nothing else."}]}],
            inferenceConfig={"maxTokens": 64, "temperature": 0.0})
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code", ""),
                exc.response.get("Error", {}).get("Message", ""))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
