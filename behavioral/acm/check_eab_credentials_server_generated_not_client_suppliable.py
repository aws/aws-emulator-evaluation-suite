"""eab-credentials-server-generated-not-client-suppliable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eab-credentials-server-generated-not-client-suppliable"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two EABs created on one endpoint with the same RoleArn get distinct server-generated key
    IDs that equal neither the RoleArn nor the binding's own ARN.
    """
    acm = ctx.client("acm")
    endpoint_arn, _ = _create_active_acme_endpoint(ctx, acm)
    role_arn = _create_eab_role(ctx)

    binding1 = _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn)
    binding2 = _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(
            AcmeExternalAccountBindingArn=binding1["AcmeExternalAccountBindingArn"]
        )
    )
    ctx.on_cleanup(
        lambda: acm.delete_acme_external_account_binding(
            AcmeExternalAccountBindingArn=binding2["AcmeExternalAccountBindingArn"]
        )
    )

    creds1 = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=binding1["AcmeExternalAccountBindingArn"]
    )
    creds2 = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=binding2["AcmeExternalAccountBindingArn"]
    )

    assert creds1["KeyId"] and creds2["KeyId"], "KeyId must never be empty"
    assert creds1["KeyId"] != role_arn and creds2["KeyId"] != role_arn, (
        f"KeyId must not be derivable from the client-supplied RoleArn, got "
        f"creds1={creds1['KeyId']!r} creds2={creds2['KeyId']!r} role_arn={role_arn!r}"
    )
    assert creds1["KeyId"] != binding1["AcmeExternalAccountBindingArn"], (
        f"binding1 KeyId {creds1['KeyId']!r} must not equal its own binding ARN "
        f"{binding1['AcmeExternalAccountBindingArn']!r}"
    )
    assert creds2["KeyId"] != binding2["AcmeExternalAccountBindingArn"], (
        f"binding2 KeyId {creds2['KeyId']!r} must not equal its own binding ARN "
        f"{binding2['AcmeExternalAccountBindingArn']!r}"
    )
    assert creds1["KeyId"] != creds2["KeyId"], (
        "two bindings created with the identical client-supplied RoleArn got the same "
        "server-generated key ID -- KeyId must be independently generated per binding"
    )


_EAB_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {"StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}},
            }
        ],
    }
)


def _create_active_acme_endpoint(ctx, acm, timeout_s: float = 180.0, interval_s: float = 5.0):
    resp = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        Contact="NOT_REQUIRED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))

    deadline = time.monotonic() + timeout_s
    endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    while endpoint["Status"] == "CREATING" and time.monotonic() < deadline:
        time.sleep(interval_s)
        endpoint = acm.describe_acme_endpoint(AcmeEndpointArn=arn)["AcmeEndpoint"]
    if endpoint["Status"] != "ACTIVE":
        raise AssertionError(
            f"ACME endpoint never reached ACTIVE (status={endpoint['Status']}, "
            f"reason={endpoint.get('FailureReason')})"
        )
    return arn, endpoint["EndpointUrl"]


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acme-eab-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_EAB_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = "acme-eab-permissions"
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

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_binding_with_retry(ctx, acm, endpoint_arn, role_arn, timeout_s: float = 90.0, interval_s: float = 5.0):
    # Newly created IAM roles are not always immediately assumable (trust-policy propagation is
    # eventually consistent), so poll on the documented AccessDeniedException until it clears.
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return resp["ExternalAccountBinding"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateAcmeExternalAccountBinding kept failing with AccessDeniedException: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
