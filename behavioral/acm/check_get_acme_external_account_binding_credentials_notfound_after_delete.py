"""get-acme-external-account-binding-credentials-notfound-after-delete."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-acme-external-account-binding-credentials-notfound-after-delete"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials raises ResourceNotFoundException once a binding is
    deleted, while a sibling live binding on the same endpoint still serves credentials."""
    acm = ctx.client("acm")
    endpoint_arn = _create_acme_endpoint(ctx)
    role_arn = _create_eab_role(ctx, "primary")
    control_role_arn = _create_eab_role(ctx, "control")

    eab_arn = _create_eab_with_role_propagation_retry(
        acm,
        AcmeEndpointArn=endpoint_arn,
        RoleArn=role_arn,
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    control_eab_arn = _create_eab_with_role_propagation_retry(
        acm,
        AcmeEndpointArn=endpoint_arn,
        RoleArn=control_role_arn,
        Tags=[{"Key": "Purpose", "Value": "sim2real-behavioral"}],
    )["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(
            AcmeExternalAccountBindingArn=control_eab_arn
        )
    )

    baseline = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    assert baseline["KeyId"]
    assert baseline["MacKey"]

    acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    def _get_deleted() -> None:
        acm.get_acme_external_account_binding_credentials(
            AcmeExternalAccountBindingArn=eab_arn
        )

    code, message = _error_code(_get_deleted)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Could not find ACME external account binding {eab_arn}.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {message!r}"
    )

    # positive control: a sibling binding on the same endpoint is unaffected
    control_creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=control_eab_arn
    )
    assert control_creds["KeyId"]
    assert control_creds["MacKey"]


def _create_eab_with_role_propagation_retry(acm, **kwargs):
    """CreateAcmeExternalAccountBinding, retrying while a just-created role propagates.

    A fresh role is briefly not passable to acm-acme.amazonaws.com and AWS reports iam:PassRole
    AccessDeniedException even when the caller is allowed it; the denial is a race."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return acm.create_acme_external_account_binding(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")



def _error_code(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
    name = ctx.unique_name("sim2real-acme-eab-notfound-")
    arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Contact="NOT_REQUIRED",
        Tags=[{"Key": "Name", "Value": name}],
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
