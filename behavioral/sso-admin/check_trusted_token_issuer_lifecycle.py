"""trusted-token-issuer-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trusted-token-issuer-lifecycle"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateTrustedTokenIssuer / UpdateTrustedTokenIssuer / DeleteTrustedTokenIssuer round-trip
    through DescribeTrustedTokenIssuer and ListTrustedTokenIssuers."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)

    name = ctx.unique_name("sim2real-behav-tti-")
    tti_arn = sso.create_trusted_token_issuer(
        InstanceArn=instance_arn,
        Name=name,
        TrustedTokenIssuerType="OIDC_JWT",
        TrustedTokenIssuerConfiguration={
            "OidcJwtConfiguration": {
                "IssuerUrl": "https://example.com/oidc",
                "ClaimAttributePath": "email",
                "IdentityStoreAttributePath": "emails.value",
                "JwksRetrievalOption": "OPEN_ID_DISCOVERY",
            }
        },
        Tags=[{"Key": "sim2real-behav", "Value": "trusted-token-issuer-lifecycle"}],
    )["TrustedTokenIssuerArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)))

    described = sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)
    assert described["Name"] == name, f"expected Name={name!r}, got {described['Name']!r}"
    assert described["TrustedTokenIssuerType"] == "OIDC_JWT", (
        f"expected TrustedTokenIssuerType=OIDC_JWT, got {described['TrustedTokenIssuerType']!r}"
    )
    issuer_url = described["TrustedTokenIssuerConfiguration"]["OidcJwtConfiguration"]["IssuerUrl"]
    assert issuer_url == "https://example.com/oidc", (
        f"expected IssuerUrl=https://example.com/oidc, got {issuer_url!r}"
    )

    listed = sso.list_trusted_token_issuers(InstanceArn=instance_arn)["TrustedTokenIssuers"]
    assert any(t["TrustedTokenIssuerArn"] == tti_arn and t["Name"] == name for t in listed), (
        f"expected {tti_arn} named {name!r} in ListTrustedTokenIssuers, got {listed!r}"
    )

    new_name = ctx.unique_name("sim2real-behav-tti-renamed-")
    sso.update_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn, Name=new_name)

    after_update = sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)
    assert after_update["Name"] == new_name, (
        f"expected Name={new_name!r} after UpdateTrustedTokenIssuer, got {after_update['Name']!r}"
    )

    sso.delete_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn)

    code, message = _error(lambda: sso.describe_trusted_token_issuer(TrustedTokenIssuerArn=tti_arn))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeTrustedTokenIssuer on a deleted issuer to raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert message == f"Could not find TrustedTokenIssuer with arn {tti_arn}.", message

    mutate_code, mutate_msg = _error(
        lambda: sso.update_trusted_token_issuer(
            TrustedTokenIssuerArn=tti_arn, Name=ctx.unique_name("sim2real-behav-tti-dead-")
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateTrustedTokenIssuer on a deleted issuer to raise ResourceNotFoundException, "
        f"got {mutate_code!r}"
    )
    assert mutate_msg == f"Could not find TrustedTokenIssuer with arn {tti_arn}.", mutate_msg


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
