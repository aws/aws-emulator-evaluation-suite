"""e2e-external-account-binding-credential-revocation-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-external-account-binding-credential-revocation-flow"
GROUP = "e2e"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Revoking an EAB sets RevokedAt and makes its credential retrieval fail with
    ValidationException, while a second, unrevoked binding on the same endpoint keeps working."""
    acm = ctx.client("acm")
    ctx.client("iam")

    role_arn = _create_eab_role(ctx)

    endpoint_arn = acm.create_acme_endpoint(
        AuthorizationBehavior="PRE_APPROVED",
        CertificateAuthority={"PublicCertificateAuthority": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-endpoint-")}],
    )["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=endpoint_arn)))

    endpoint_status = _poll_until(
        lambda: acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]["Status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=120.0,
    )
    assert endpoint_status == "ACTIVE", f"expected endpoint ACTIVE, got {endpoint_status!r}"

    binding_a_arn = _create_binding_with_retry(ctx, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_a_arn)
        )
    )

    creds_a = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_a_arn)
    assert creds_a["KeyId"], "expected a KeyId in the pre-revoke credentials response for binding A"
    assert creds_a["MacKey"], "expected a MacKey in the pre-revoke credentials response for binding A"

    domain = f"{ctx.unique_name('sim2realeab').rstrip('-')}.example.com".lower()
    validation_arn = acm.create_acme_domain_validation(
        AcmeEndpointArn=endpoint_arn,
        DomainName=domain,
        PrevalidationOptions={"DnsPrevalidation": {}},
        Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-dv-")}],
    )["AcmeDomainValidationArn"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: acm.delete_acme_domain_validation(AcmeDomainValidationArn=validation_arn))
    )
    described_domain = acm.describe_acme_domain_validation(AcmeDomainValidationArn=validation_arn)[
        "AcmeDomainValidation"
    ]["DomainName"]
    assert described_domain == domain, f"expected domain validation for {domain!r}, got {described_domain!r}"

    # Positive control binding: created and used the same way, must keep working
    # after binding A is revoked below.
    binding_b_arn = _create_binding_with_retry(ctx, endpoint_arn, role_arn)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_b_arn)
        )
    )

    # Break exactly one thing: revoke binding A only.
    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_a_arn)

    revoked_binding = _poll_until(
        lambda: acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_a_arn)[
            "ExternalAccountBinding"
        ],
        lambda b: b.get("RevokedAt") is not None,
        timeout_s=30.0,
    )
    assert revoked_binding["RevokedAt"] is not None, f"binding A never showed RevokedAt: {revoked_binding!r}"

    # The revoked binding still exists (RevokedAt is set), so AWS answers ValidationException,
    # not ResourceNotFoundException.
    code, message = _error(
        lambda: acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_a_arn)
    )
    assert code == "ValidationException", f"unexpected error after revoke: {code!r}"
    expected_message = f"The ACME external account binding {binding_a_arn} has been revoked."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control still succeeds: binding B was never revoked.
    creds_b = acm.get_acme_external_account_binding_credentials(AcmeExternalAccountBindingArn=binding_b_arn)
    assert creds_b["KeyId"], "expected a KeyId in binding B's credentials response (never revoked)"
    assert creds_b["MacKey"], "expected a MacKey in binding B's credentials response (never revoked)"
    unrevoked_binding = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=binding_b_arn)[
        "ExternalAccountBinding"
    ]
    assert unrevoked_binding.get("RevokedAt") is None, (
        f"binding B should remain unrevoked (positive control), got RevokedAt={unrevoked_binding.get('RevokedAt')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _error(fn):
    """Call fn(); return its error (code, message). A success raises rather than returning a sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_eab_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-eab-role-")
    trust_policy = {
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["acm:RequestCertificate", "acm:RevokeCertificate"],
                "Resource": "*",
            }
        ],
    }
    policy_name = ctx.unique_name("sim2real-acm-eab-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_binding_with_retry(ctx, endpoint_arn, role_arn, timeout_s=45.0, interval_s=3.0):
    """CreateAcmeExternalAccountBinding verifies the role is assumable, which can
    transiently fail with AccessDeniedException while a freshly created IAM role
    propagates -- retry on that specific error only."""
    from botocore.exceptions import ClientError

    acm = ctx.client("acm")
    tag_value = ctx.unique_name("sim2real-acm-eab-")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = acm.create_acme_external_account_binding(
                AcmeEndpointArn=endpoint_arn,
                RoleArn=role_arn,
                Tags=[{"Key": "Name", "Value": tag_value}],
            )
            bound_role_arn = resp["ExternalAccountBinding"]["RoleArn"]
            assert bound_role_arn == role_arn, f"expected RoleArn {role_arn!r}, got {bound_role_arn!r}"
            return resp["ExternalAccountBinding"]["AcmeExternalAccountBindingArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"binding creation kept failing with AccessDeniedException: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
