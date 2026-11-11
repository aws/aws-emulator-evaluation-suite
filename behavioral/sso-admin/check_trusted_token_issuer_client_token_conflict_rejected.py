"""trusted-token-issuer-client-token-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trusted-token-issuer-client-token-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateTrustedTokenIssuer replayed with the same ClientToken returns the original ARN; the same
    ClientToken with a different config is a ConflictException (exact message) that leaves the issuer
    unchanged, and a fresh ClientToken with the same Name creates a distinct issuer keeping that Name."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    name = ctx.unique_name("sim2real-behav-tti-")
    token = ctx.unique_name("sim2real-behav-token-")

    def _config(issuer_url):
        return {
            "OidcJwtConfiguration": {
                "IssuerUrl": issuer_url,
                "ClaimAttributePath": "email",
                "IdentityStoreAttributePath": "emails.value",
                "JwksRetrievalOption": "OPEN_ID_DISCOVERY",
            }
        }

    tti_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=name,
        ClientToken=token,
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration=_config("https://example.com/oidc-first"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TrustedTokenIssuerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)))

    # Replaying the identical request (same ClientToken, same params) is idempotent.
    replay_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=name,
        ClientToken=token,
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration=_config("https://example.com/oidc-first"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TrustedTokenIssuerArn"]
    assert replay_arn == tti_arn, f"idempotent replay should return the original ARN {tti_arn!r}, got {replay_arn!r}"

    # Reusing the same ClientToken with a different configuration is a conflict.
    code, message = _error(
        lambda: sso.create_trusted_token_issuer(
            InstanceArn=instance_arn,
            Name=name,
            ClientToken=token,
            TrustedTokenIssuerType="OIDC_JWT",
            TrustedTokenIssuerConfiguration=_config("https://example.com/oidc-second"),
        )
    )
    assert code == "ConflictException", f"expected ConflictException for a reused ClientToken with a different config, got {code!r}"
    assert message == "The request parameters are different from that of a previous request", message

    # Effect absent: the original issuer's configuration is untouched.
    described = sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)
    actual_url = described["TrustedTokenIssuerConfiguration"]["OidcJwtConfiguration"]["IssuerUrl"]
    assert actual_url == "https://example.com/oidc-first", (
        f"rejected conflict must not mutate the original issuer, expected IssuerUrl "
        f"'https://example.com/oidc-first', got {actual_url!r}"
    )

    # A *fresh* ClientToken with the identical Name is, notably, allowed: Name is not a
    # uniqueness key for trusted token issuers, so this creates a genuinely second issuer.
    other_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=name,
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration=_config("https://example.com/oidc-other"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["TrustedTokenIssuerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=other_arn)))
    assert other_arn != tti_arn, f"a fresh ClientToken with the same Name should create a distinct issuer, got the same ARN {other_arn!r}"
    other_name = sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=other_arn)["Name"]
    assert other_name == name, f"expected the second issuer to keep the shared Name {name!r}, got {other_name!r}"


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

