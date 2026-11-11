"""revoked-eab-credentials-access-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "revoked-eab-credentials-access-rejected"
GROUP = "server-side"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAcmeExternalAccountBindingCredentials succeeds for an active binding; after revocation
    the binding persists with RevokedAt set, and credential reads raise ValidationException."""
    acm = ctx.client("acm")

    role_arn = _create_eab_role(ctx)
    endpoint_arn = _create_acme_endpoint(ctx)
    _wait_for_endpoint_active(ctx, endpoint_arn)
    eab = _create_eab(ctx, endpoint_arn, role_arn)
    eab_arn = eab["AcmeExternalAccountBindingArn"]

    # Positive control: credentials are retrievable while the binding is active.
    creds = acm.get_acme_external_account_binding_credentials(
        AcmeExternalAccountBindingArn=eab_arn
    )
    assert creds["KeyId"] and creds["MacKey"], (
        f"expected a non-empty KeyId/MacKey before revocation, got {creds!r}"
    )

    before = acm.describe_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)[
        "ExternalAccountBinding"
    ]
    assert "RevokedAt" not in before or before["RevokedAt"] is None, (
        f"expected no RevokedAt before revocation, got {before.get('RevokedAt')!r}"
    )

    acm.revoke_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)

    after = _poll_until(
        lambda: acm.describe_acme_external_account_binding(
            AcmeExternalAccountBindingArn=eab_arn
        )["ExternalAccountBinding"],
        lambda desc: desc.get("RevokedAt") is not None,
        timeout_s=30,
        interval_s=2,
    )
    assert after["RevokedAt"] is not None, "expected RevokedAt to be populated after revocation"
    # The record still exists (revocation is not deletion): identity fields are unchanged.
    assert after["AcmeExternalAccountBindingArn"] == eab_arn, (
        f"expected ARN {eab_arn!r} unchanged after revocation, got {after['AcmeExternalAccountBindingArn']!r}"
    )
    assert after["RoleArn"] == role_arn, (
        f"expected RoleArn {role_arn!r} unchanged after revocation, got {after['RoleArn']!r}"
    )

    # Credential access is rejected once the binding has been revoked: this
    # management-plane read re-validates revocation state and fails with a
    # ValidationException rather than returning the (still-existing) secret material.
    code, message = _client_error(
        lambda: acm.get_acme_external_account_binding_credentials(
            AcmeExternalAccountBindingArn=eab_arn
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"The ACME external account binding {eab_arn} has been revoked."
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    """Return (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a refusal, but the call succeeded and returned {result!r}")


def _create_eab_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-acm-eab-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "acm-acme.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
                "Condition": {
                    "StringLikeIfExists": {"sts:SourceIdentity": "acm-acme-*"}
                },
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_acme_endpoint(ctx, **overrides: Any) -> str:
    acm = ctx.client("acm")
    params: dict[str, Any] = {
        "AuthorizationBehavior": "PRE_APPROVED",
        "CertificateAuthority": {"PublicCertificateAuthority": {}},
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-acm-endpoint-")}],
    }
    params.update(overrides)
    arn = acm.create_acme_endpoint(**params)["AcmeEndpointArn"]
    ctx.on_cleanup(lambda: acm.delete_acme_endpoint(AcmeEndpointArn=arn))
    return arn


def _wait_for_endpoint_active(ctx, endpoint_arn, timeout_s=180.0, interval_s=5.0):
    acm = ctx.client("acm")

    def probe():
        return acm.describe_acme_endpoint(AcmeEndpointArn=endpoint_arn)["AcmeEndpoint"]

    def done(desc):
        if desc["Status"] == "FAILED":
            raise AssertionError(f"AcmeEndpoint {endpoint_arn} FAILED: {desc.get('FailureReason')}")
        return desc["Status"] == "ACTIVE"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _create_eab(ctx, endpoint_arn, role_arn):
    acm = ctx.client("acm")

    def attempt():
        return acm.create_acme_external_account_binding(
            AcmeEndpointArn=endpoint_arn, RoleArn=role_arn
        )["ExternalAccountBinding"]

    # A freshly created IAM role can briefly be invisible to other services (IAM eventual
    # consistency), so retry AccessDenied for a bounded window before treating it as real.
    deadline = time.monotonic() + 30.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            eab = attempt()
            eab_arn = eab["AcmeExternalAccountBindingArn"]
            ctx.on_cleanup(
                lambda arn=eab_arn: _delete_eab_if_present(acm, arn)
            )
            return eab
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code != "AccessDeniedException":
                raise
            last_err = err
            time.sleep(3)
    raise AssertionError(f"CreateAcmeExternalAccountBinding never succeeded: {last_err}")


def _delete_eab_if_present(acm, eab_arn):
    from botocore.exceptions import ClientError

    try:
        acm.delete_acme_external_account_binding(AcmeExternalAccountBindingArn=eab_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
