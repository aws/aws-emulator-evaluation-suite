"""describe-resource-policies-without-permission-denied-policy-unexposed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-resource-policies-without-permission-denied-policy-unexposed"
GROUP = "error-semantics"
SERVICES = ["logs", "iam", "sts"]

_DENIED = "AccessDeniedException"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, unless it is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def expect_error(fn, code, message):
    """Call fn(); assert it raises exactly (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected ({code!r}, {message!r}), but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last value: {last!r}")


def _policy_document():
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealBehavioral",
                    "Effect": "Allow",
                    "Principal": {"Service": ["route53.amazonaws.com"]},
                    "Action": "logs:PutLogEvents",
                    "Resource": "*",
                }
            ],
        }
    )


def _find(logs, policy_name):
    for entry in logs.describe_resource_policies().get("resourcePolicies", []):
        if entry.get("policyName") == policy_name:
            return entry
    return None


def _normalized(policy_document_json):
    """Parse a stored policyDocument, collapsing a single-element list to its bare scalar.

    AWS stores a lone ``Principal.Service`` value as a scalar even when submitted as a
    one-element list, so compare structurally-equivalent forms rather than the raw string.
    """
    doc = json.loads(policy_document_json)
    service = doc["Statement"][0]["Principal"]["Service"]
    if isinstance(service, list) and len(service) == 1:
        doc["Statement"][0]["Principal"]["Service"] = service[0]
    return doc


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:logs-resource-policy",
)
def run(ctx) -> None:
    """A principal without logs:DescribeResourcePolicies is denied the call and never sees the
    account's resource policy; granting the action to the identical principal then lets the
    identical call succeed and return the exact, unaltered policy document.
    """
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    policy_name = ctx.unique_name("sim2real-behav-rp-noperm-")
    policy_document = _policy_document()
    logs.put_resource_policy(policyName=policy_name, policyDocument=policy_document)
    ctx.on_cleanup(_teardown(lambda: logs.delete_resource_policy(policyName=policy_name), "ResourceNotFoundException"))

    baseline = _find(logs, policy_name)
    assert baseline is not None, f"resource policy {policy_name!r} not visible right after PutResourcePolicy"
    assert _normalized(baseline["policyDocument"]) == _normalized(policy_document), (
        f"stored policyDocument {baseline['policyDocument']!r} != submitted {policy_document!r}"
    )

    role_name = ctx.unique_name("sim2real-behav-nodescrp-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav DescribeResourcePolicies denial scenario",
        Tags=[{"Key": "sim2real", "Value": "describe-resource-policies-without-permission-denied"}],
    )

    def _delete_role(_n=role_name):
        for inline_name in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=_n, PolicyName=inline_name)
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_delete_role)

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-read-only",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        # logs:DescribeResourcePolicies is ABSENT -- the one broken thing. There
                        # is no explicit Deny; the refusal below is IAM's implicit one.
                        "Effect": "Allow",
                        "Action": "logs:DescribeLogGroups",
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    deadline = time.monotonic() + 60.0
    creds = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
                RoleSessionName="sim2real-behav-nodescrp",
            )["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(3.0)
    assert creds is not None, (
        f"AssumeRole on the freshly-created role {role_name!r} never succeeded within 60s: {last_exc!r}"
    )

    limited = ctx.client(
        "logs",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/sim2real-behav-nodescrp"

    def _control_attempt():
        try:
            limited.describe_log_groups(logGroupNamePrefix="sim2real-behav-nodescrp-control")
            return "done"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    # Positive control, which doubles as the bounded retry past IAM propagation.
    _poll_until(
        _control_attempt,
        lambda r: r == "done",
        description="the limited principal's read-only policy becomes effective",
    )

    # DescribeResourcePolicies names no specific resource, so IAM's denial cites the generic
    # account-level placeholder ARN rather than omitting a resource clause.
    placeholder_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group::log-stream:"
    denied = (
        _DENIED,
        f"User: {session_arn} is not authorized to perform: logs:DescribeResourcePolicies on "
        f"resource: {placeholder_arn} because no identity-based policy allows the "
        f"logs:DescribeResourcePolicies action",
    )
    expect_error(lambda: limited.describe_resource_policies(), *denied)

    # The forbidden effect did not happen: an independent read (through the original,
    # unrestricted client) still finds the exact, unaltered policy document.
    after_denial = _find(logs, policy_name)
    assert after_denial is not None and _normalized(after_denial["policyDocument"]) == _normalized(
        policy_document
    ), (
        f"the denied DescribeResourcePolicies call must not have altered the stored policy, "
        f"got {after_denial!r}"
    )

    # Restore, on the SAME denied principal: grant logs:DescribeResourcePolicies to the
    # identical role and re-issue the identical call.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-behav-grant-describe-resource-policies",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "logs:DescribeResourcePolicies", "Resource": "*"}],
            }
        ),
    )

    def _describe_attempt():
        try:
            return _find(limited, policy_name)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    granted = _poll_until(
        _describe_attempt,
        lambda r: isinstance(r, dict),
        timeout_s=180.0,
        description="the identical DescribeResourcePolicies call succeeds once the grant propagates",
    )
    assert _normalized(granted["policyDocument"]) == _normalized(policy_document), (
        f"a caller WITH logs:DescribeResourcePolicies must see the exact document, got {granted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
