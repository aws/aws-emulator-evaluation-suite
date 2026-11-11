"""access-denied-sandbox-eval."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """The captured AWS error code, or a sentinel that cannot be mistaken for one on success."""
    return _error(fn)[0]

def _error(fn):
    """The captured AWS error (code, message), or a sentinel pair on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    return "UNEXPECTED_SUCCESS", None

def _poll(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last

def _denied_message(ctx, user_arn, action):
    """The implicit-deny message AWS returns for `action` called by `user_arn`."""
    account = user_arn.split(":")[4]
    return (f"User: {user_arn} is not authorized to perform: appsync:{action} on resource: "
            f"arn:aws:appsync:{ctx.region}:{account}:* because no identity-based policy allows "
            f"the appsync:{action} action")

def _propagation_s(ctx):
    """IAM grant changes can take minutes to reach AppSync; the poll is capped by the run budget."""
    return min(300.0, ctx.time_left())

def _delete_policy_if_present(iam, user):
    """Teardown DeleteUserPolicy; the check deletes the grant itself, so NoSuchEntity is gone."""
    try:
        iam.delete_user_policy(UserName=user, PolicyName=_POLICY_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _target_client(ctx, service, creds):
    """A `service` client on the run's target, signing with `creds`."""
    return ctx.client(service, creds=creds)

CHECK = "access-denied-sandbox-eval"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

_POLICY_NAME = "sim2real-behav-sandbox-eval"

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EvaluateCode and EvaluateMappingTemplate succeed under an identity grant, are refused with
    AccessDeniedException once it is removed, and succeed again when it is reattached.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-denied-")
    user_arn = iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    def _cleanup_user(_u=user, _iam=iam):
        for k in _iam.list_access_keys(UserName=_u).get("AccessKeyMetadata", []):
            _iam.delete_access_key(UserName=_u, AccessKeyId=k["AccessKeyId"])
        _iam.delete_user(UserName=_u)
    ctx.on_cleanup(_cleanup_user)

    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))
    principal = _target_client(ctx, "appsync", {
        "aws_access_key_id": key["AccessKeyId"],
        "aws_secret_access_key": key["SecretAccessKey"],
    })

    runtime = {"name": "APPSYNC_JS", "runtimeVersion": "1.0.0"}
    code_body = (
        "export function request(ctx) { return {}; }\n"
        "export function response(ctx) { return ctx.result; }\n"
    )
    context = "{}"

    def _eval_code():
        principal.evaluate_code(runtime=runtime, code=code_body, context=context, function="response")

    def _eval_template():
        principal.evaluate_mapping_template(template="$util.toJson($context)", context=context)

    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["appsync:EvaluateCode", "appsync:EvaluateMappingTemplate"],
            "Resource": "*",
        }],
    })
    iam.put_user_policy(UserName=user, PolicyName=_POLICY_NAME, PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_policy_if_present(iam, user))

    # Positive control; the poll absorbs IAM propagation of the new key and the grant.
    granted_code = _poll(
        lambda: _error_code(_eval_code),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90, interval_s=3,
        description="the identity policy becomes effective for appsync:EvaluateCode",
    )
    assert granted_code == "UNEXPECTED_SUCCESS", (
        f"EvaluateCode: the identity policy grants appsync:EvaluateCode, so the real signed call "
        f"must succeed before the grant is removed; got {granted_code!r}"
    )
    granted_template = _poll(
        lambda: _error_code(_eval_template),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=90, interval_s=3,
        description="the identity policy becomes effective for appsync:EvaluateMappingTemplate",
    )
    assert granted_template == "UNEXPECTED_SUCCESS", (
        f"EvaluateMappingTemplate: the identity policy grants appsync:EvaluateMappingTemplate, so "
        f"the real signed call must succeed before the grant is removed; got {granted_template!r}"
    )

    # Removing the grant leaves an implicit deny on every action.
    iam.delete_user_policy(UserName=user, PolicyName=_POLICY_NAME)

    denied_code, denied_message = _poll(
        lambda: _error(_eval_code),
        lambda c: c[0] == "AccessDeniedException",
        timeout_s=_propagation_s(ctx), interval_s=3,
        description="removing the grant denies appsync:EvaluateCode",
    )
    assert denied_code == "AccessDeniedException", (
        f"EvaluateCode: expected AccessDeniedException for an unauthorized principal, got {denied_code}"
    )
    expected = _denied_message(ctx, user_arn, "EvaluateCode")
    assert denied_message == expected, f"EvaluateCode: expected {expected!r}, got {denied_message!r}"
    denied_template, template_message = _poll(
        lambda: _error(_eval_template),
        lambda c: c[0] == "AccessDeniedException",
        timeout_s=_propagation_s(ctx), interval_s=3,
        description="removing the grant denies appsync:EvaluateMappingTemplate",
    )
    assert denied_template == "AccessDeniedException", (
        f"EvaluateMappingTemplate: expected AccessDeniedException for an unauthorized principal, "
        f"got {denied_template}"
    )
    expected = _denied_message(ctx, user_arn, "EvaluateMappingTemplate")
    assert template_message == expected, (
        f"EvaluateMappingTemplate: expected {expected!r}, got {template_message!r}"
    )

    # Restoring the grant proves the denial tracked the grant, not an unrelated failure.
    iam.put_user_policy(UserName=user, PolicyName=_POLICY_NAME, PolicyDocument=policy_doc)
    restored_code = _poll(
        lambda: _error_code(_eval_code),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_propagation_s(ctx), interval_s=3,
        description="reattaching the grant restores appsync:EvaluateCode",
    )
    assert restored_code == "UNEXPECTED_SUCCESS", (
        f"EvaluateCode: reattaching the identical grant must restore the identical call; got "
        f"{restored_code!r}"
    )
    restored_template = _poll(
        lambda: _error_code(_eval_template),
        lambda c: c == "UNEXPECTED_SUCCESS",
        timeout_s=_propagation_s(ctx), interval_s=3,
        description="reattaching the grant restores appsync:EvaluateMappingTemplate",
    )
    assert restored_template == "UNEXPECTED_SUCCESS", (
        f"EvaluateMappingTemplate: reattaching the identical grant must restore the identical call; "
        f"got {restored_template!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
