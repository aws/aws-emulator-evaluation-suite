"""delete-trusted-token-issuer-while-referenced-by-grant."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-trusted-token-issuer-while-referenced-by-grant"
GROUP = "state-machine"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DeleteTrustedTokenIssuer succeeds on an issuer an application's JWT-bearer grant still references:
    Describe and a second delete then answer ResourceNotFoundException with the exact message, and
    GetApplicationGrant still lists the deleted issuer's ARN (the grant is not cascade-cleaned)."""

    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_application(ApplicationArn=app_arn)))

    tti_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=ctx.unique_name("sim2real-behav-tti-"),
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration={
            "OidcJwtConfiguration": {
                "IssuerUrl": "https://example.com/oidc",
                "ClaimAttributePath": "email",
                "IdentityStoreAttributePath": "emails.value",
                "JwksRetrievalOption": "OPEN_ID_DISCOVERY",
            }
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["TrustedTokenIssuerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)))

    grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    sso.put_application_grant(
        ApplicationArn=app_arn,
        GrantType=grant_type,
        Grant={
            "JwtBearer": {
                "AuthorizedTokenIssuers": [
                    {"TrustedTokenIssuerArn": tti_arn, "AuthorizedAudiences": ["sim2real-test-audience"]}
                ]
            }
        },
    )

    # No conflict: the issuer deletes cleanly despite the referencing grant.
    sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)

    code_after, msg_after = _error(lambda: sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn))
    assert code_after == "ResourceNotFoundException", (
        f"expected DescribeTrustedTokenIssuer on the deleted issuer to 404 with "
        f"ResourceNotFoundException, got {code_after!r}"
    )
    assert msg_after == f"Could not find TrustedTokenIssuer with arn {tti_arn}.", msg_after

    # A mutation on the dead id also fails, not just the read.
    code_redelete, msg_redelete = _error(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn))
    assert code_redelete == "ResourceNotFoundException", (
        f"expected a second DeleteTrustedTokenIssuer on the already-deleted issuer to fail with "
        f"ResourceNotFoundException, got {code_redelete!r}"
    )
    assert msg_redelete == f"Could not find TrustedTokenIssuer with arn {tti_arn}.", msg_redelete

    # The referencing grant is left dangling rather than cascade-cleaned.
    grant = sso.get_application_grant(ApplicationArn=app_arn, GrantType=grant_type)["Grant"]
    referenced_arns = {
        issuer["TrustedTokenIssuerArn"] for issuer in grant["JwtBearer"]["AuthorizedTokenIssuers"]
    }
    assert tti_arn in referenced_arns, (
        f"expected the deleted issuer {tti_arn!r} to remain listed on the grant's "
        f"AuthorizedTokenIssuers (no cascade cleanup), got {sorted(referenced_arns)!r}"
    )


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _pick_oauth_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
