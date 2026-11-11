"""put-resource-policy-refused-for-unsupported-resource-types."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# PutResourcePolicy's documentation says it is available only for Runtime and Gateway, but
# Gateway, Browser and CodeInterpreter all accept a policy. WorkloadIdentity and
# ApiKeyCredentialProvider are refused with ValidationException, and an ARN naming no real
# resource type with AccessDeniedException. The DeleteResourcePolicy effect is not asserted.

CHECK = "put-resource-policy-refused-for-unsupported-resource-types"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy accepts Gateway, Browser and CodeInterpreter ARNs, refuses WorkloadIdentity
    and ApiKeyCredentialProvider ARNs with ValidationException and a non-resource-type ARN with
    AccessDeniedException, storing no policy on refused resources and keeping accepted ones."""
    bac = ctx.client("bedrock-agentcore-control")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_gateway_role(ctx)

    gateway_arn = _create_ready_gateway(ctx, bac, role_arn)
    browser_arn = _create_ready_browser(ctx, bac)
    code_interpreter_arn = _create_ready_code_interpreter(ctx, bac)

    wi_name = ctx.unique_name("sim2realrpwi")[:48]
    wi = bac.create_workload_identity(name=wi_name, tags={"sim2real": CHECK})
    wi_arn = wi["workloadIdentityArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_workload_identity(name=wi_name)))

    cp_name = ctx.unique_name("sim2realrpcp")[:48]
    cp = bac.create_api_key_credential_provider(
        name=cp_name, apiKey="sim2real-probe-key", tags={"sim2real": CHECK}
    )
    cp_arn = cp["credentialProviderArn"]
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: bac.delete_api_key_credential_provider(name=cp_name))
    )

    # One document shape, reused verbatim across every ARN so the ONLY thing that differs between
    # calls is the resource type.
    def document(resource_arn):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Sim2RealScopeProbe",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "bedrock-agentcore:InvokeGateway",
                        "Resource": resource_arn,
                    }
                ],
            }
        )

    docs = {
        "gateway": document(gateway_arn),
        "browser": document(browser_arn),
        "code interpreter": document(code_interpreter_arn),
    }

    # Positive controls: every AgentCore-owned execution-sandbox resource type accepts a policy,
    # each proven by an independent read -- a different operation than the mutation.
    for label, arn in (
        ("gateway", gateway_arn),
        ("browser", browser_arn),
        ("code interpreter", code_interpreter_arn),
    ):
        doc = docs[label]
        put_resp = bac.put_resource_policy(resourceArn=arn, policy=doc)
        ctx.on_cleanup(
            lambda arn=arn: _safe_delete(lambda: bac.delete_resource_policy(resourceArn=arn))
        )
        assert json.loads(put_resp["policy"]) == json.loads(doc), (
            f"PutResourcePolicy on the {label} echoed a different document: {put_resp['policy']!r}"
        )
        stored = bac.get_resource_policy(resourceArn=arn)
        assert json.loads(stored["policy"]) == json.loads(doc), (
            f"GetResourcePolicy on the {label} returned {stored.get('policy')!r}, expected the "
            f"document just stored"
        )

    # The subject: resource types PutResourcePolicy genuinely refuses, and the specific code each
    # is refused with. No restore leg exists by construction -- a WorkloadIdentity can never
    # become a Gateway, and a malformed resource type can never become a real one.
    bogus_arn = (
        f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:totally-bogus-type/does-not-exist-xyz"
    )
    for label, unsupported_arn, expected_code in (
        ("workload identity", wi_arn, "ValidationException"),
        ("api key credential provider", cp_arn, "ValidationException"),
        ("an ARN naming no real resource type", bogus_arn, "AccessDeniedException"),
    ):
        code = _error_code_or_raise(
            lambda unsupported_arn=unsupported_arn: bac.put_resource_policy(
                resourceArn=unsupported_arn, policy=document(unsupported_arn)
            ),
            subject=f"PutResourcePolicy on {label} ({unsupported_arn})",
        )
        assert code == expected_code, (
            f"expected PutResourcePolicy on {label} to be refused with {expected_code!r}, got "
            f"{code!r} for {unsupported_arn!r}"
        )
        # Effect absent, read at the resource itself, through a different operation.
        try:
            leaked = bac.get_resource_policy(resourceArn=unsupported_arn)
        except ClientError as err:
            get_code = err.response["Error"]["Code"]
            assert get_code == expected_code, (
                f"GetResourcePolicy on {label} failed with {get_code!r}; expected the same "
                f"{expected_code!r} PutResourcePolicy was refused with"
            )
        else:
            assert not leaked.get("policy"), (
                f"a policy was stored on {label} {unsupported_arn!r} despite PutResourcePolicy "
                f"being refused with {code!r}: {leaked['policy']!r}"
            )

    # The refusals must not have disturbed the policies already accepted.
    for label, arn in (
        ("gateway", gateway_arn),
        ("browser", browser_arn),
        ("code interpreter", code_interpreter_arn),
    ):
        final = bac.get_resource_policy(resourceArn=arn)
        assert json.loads(final["policy"]) == json.loads(docs[label]), (
            f"the {label}'s policy changed while out-of-scope PutResourcePolicy calls were "
            f"refused: {final.get('policy')!r}"
        )



# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously. The
# runner swallows a cleanup's exception, so a bare delete in on_cleanup leaked even on PASS.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_gateway(control, gateway_id):
    """Delete every target first (DeleteGateway is refused while one exists), then the gateway."""
    try:
        pages = control.get_paginator("list_gateway_targets").paginate(gatewayIdentifier=gateway_id)
        target_ids = [t["targetId"] for page in pages for t in page.get("items", [])]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    for target_id in target_ids:
        _ac_delete_and_wait(
            lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)["status"],
            lambda: control.delete_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
            what=f"gateway target {target_id}",
        )
    _ac_delete_and_wait(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id)["status"],
        lambda: control.delete_gateway(gatewayIdentifier=gateway_id),
        what=f"gateway {gateway_id}",
    )


def _poll_until(probe, predicate, reason, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _error_code_or_raise(fn, subject):
    """RAISES on unexpected success rather than returning a falsy sentinel."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"{subject} unexpectedly SUCCEEDED; expected it to be refused")


def _create_ready_gateway(ctx, bac, role_arn):
    gateway_name = _gateway_name(ctx, "sim2real-gw-rpscope-")
    gw = _retry_until_role_usable(
        lambda: bac.create_gateway(
            name=gateway_name,
            roleArn=role_arn,
            authorizerType="AWS_IAM",
            tags={"sim2real": CHECK},
        )
    )
    gateway_id = gw["gatewayId"]
    ctx.on_cleanup(lambda: _ac_delete_gateway(bac, gateway_id))
    settled = _poll_until(
        lambda: bac.get_gateway(gatewayIdentifier=gateway_id),
        lambda g: g["status"] in ("READY", "FAILED"),
        "the gateway to reach a terminal create status",
        timeout_s=240.0,
    )
    assert settled["status"] == "READY", (
        f"gateway {gateway_id} did not become READY: status={settled['status']!r} "
        f"statusReasons={settled.get('statusReasons')!r}"
    )
    return settled["gatewayArn"]


def _create_ready_browser(ctx, bac):
    name = _sandbox_name(ctx, "sim2realrpbrw")
    created = bac.create_browser(
        name=name,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    browser_id = created["browserId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: bac.get_browser(browserId=browser_id)["status"],
            lambda: bac.delete_browser(browserId=browser_id),
            what=f"browser {browser_id}",
        )
    )
    settled = _poll_until(
        lambda: bac.get_browser(browserId=browser_id),
        lambda b: b["status"] != "CREATING",
        "the browser to leave CREATING",
        timeout_s=180.0,
    )
    assert settled["status"] == "READY", (
        f"browser {browser_id} did not become READY: status={settled['status']!r}"
    )
    return settled["browserArn"]


def _create_ready_code_interpreter(ctx, bac):
    name = _sandbox_name(ctx, "sim2realrpci")
    created = bac.create_code_interpreter(
        name=name,
        networkConfiguration={"networkMode": "PUBLIC"},
        tags={"sim2real": CHECK},
    )
    ci_id = created["codeInterpreterId"]
    ctx.on_cleanup(
        lambda: _ac_delete_and_wait(
            lambda: bac.get_code_interpreter(codeInterpreterId=ci_id)["status"],
            lambda: bac.delete_code_interpreter(codeInterpreterId=ci_id),
            what=f"code interpreter {ci_id}",
        )
    )
    settled = _poll_until(
        lambda: bac.get_code_interpreter(codeInterpreterId=ci_id),
        lambda c: c["status"] != "CREATING",
        "the code interpreter to leave CREATING",
        timeout_s=180.0,
    )
    assert settled["status"] == "READY", (
        f"code interpreter {ci_id} did not become READY: status={settled['status']!r}"
    )
    return settled["codeInterpreterArn"]


def _sandbox_name(ctx, prefix):
    """SandboxName is ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(f"{prefix}-")
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "s" + safe
    return safe[:48]


def _gateway_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c == "-")[:48].rstrip("-")


def _create_gateway_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bac-rpscope-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _retry_until_role_usable(fn, timeout_s=120.0, interval_s=6.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("AccessDeniedException", "ValidationException") and (
                "role" in message.lower()
            ):
                last = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s; last error={last}")


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
