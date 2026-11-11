"""create-acme-external-account-binding-duplicate-key-conflict."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-acme-external-account-binding-duplicate-key-conflict"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAcmeExternalAccountBinding retried with a used IdempotencyToken but a different RoleArn
    is rejected with ConflictException; the same RoleArn returns the same binding ARN."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    role_a = _create_eab_role(ctx, "a")
    role_b = _create_eab_role(ctx, "b")
    token = ctx.unique_name("sim2real-acme-eab-tok-")

    binding = _through_iam_propagation(
        lambda: acm.create_acme_external_account_binding(
            AcmeEndpointArn=endpoint_arn, RoleArn=role_a, IdempotencyToken=token
        )
    )["ExternalAccountBinding"]
    eab_arn = binding["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    assert binding["RoleArn"] == role_a, (
        f"expected the initial binding to be created with role_a, got {binding['RoleArn']}"
    )

    def _conflicting_retry() -> None:
        acm.create_acme_external_account_binding(
            AcmeEndpointArn=endpoint_arn, RoleArn=role_b, IdempotencyToken=token
        )

    code, message = _error_code(lambda: _through_iam_propagation(_conflicting_retry))
    assert code == "ConflictException", f"expected ConflictException, got {code} ({message!r})"
    expected_message = "Idempotency token was already used with different request parameters"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the binding's role was not silently changed to role_b
    described = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=eab_arn
    )["ExternalAccountBinding"]
    assert described["RoleArn"] == role_a, (
        f"conflicting retry must not change the bound role, got {described['RoleArn']}"
    )

    # positive control: retrying with the *same* parameters is idempotent
    same = acm.create_acme_external_account_binding(
        AcmeEndpointArn=endpoint_arn, RoleArn=role_a, IdempotencyToken=token
    )["ExternalAccountBinding"]
    assert same["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"retrying with the same token/role must be idempotent, got {same['AcmeExternalAccountBindingArn']}"
    )

    # terminal read: independent of the idempotent retry's own response, confirm
    # the binding still resolves to role_a at the destination
    final = acm.describe_acme_external_account_binding(
        AcmeExternalAccountBindingArn=eab_arn
    )["ExternalAccountBinding"]
    assert final["RoleArn"] == role_a, (
        f"expected role_a to persist through the idempotent retry, got {final['RoleArn']}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _through_iam_propagation(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Call fn(), retrying while IAM has not yet propagated a freshly created role to ACM
    (iam:PassRole on the new role reads AccessDeniedException in that window). Any other
    outcome, success or error, is returned or raised as is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_for_endpoint_terminal(
    ctx, arn: str, timeout_s: float = 120.0, interval_s: float = 3.0
) -> dict[str, Any]:
    acm = ctx.client("acm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
        if endpoint["Status"] in ("ACTIVE", "FAILED"):
            if endpoint["Status"] != "ACTIVE":
                raise AssertionError(
                    f"endpoint entered FAILED: {endpoint.get('FailureReason')}"
                )
            return endpoint
        time.sleep(interval_s)
    raise AssertionError(f"AcmeEndpoint {arn} stayed CREATING past {timeout_s}s")


def _create_acme_endpoint(ctx) -> str:
    acm = ctx.client("acm")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    _wait_for_endpoint_terminal(ctx, arn)
    return arn


def _create_eab_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-acme-eab-role-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": [
                    "sts:AssumeRole",
                    "sts:TagSession",
                    "sts:SetSourceIdentity",
                ],
                "Condition": {
                    "StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-acme-eab-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
