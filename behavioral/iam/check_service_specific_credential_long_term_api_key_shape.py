"""service-specific-credential-long-term-api-key-shape."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-specific-credential-long-term-api-key-shape"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A Bedrock API-key credential returns ServiceCredentialSecret and an ExpirationDate ~30 days
    out, never ServiceUserName/ServicePassword; its alias is `{user}-at-{account}`, and a later
    ListServiceSpecificCredentials read never carries the secret.
    """
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-behav-ssckeyshape-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    created = iam.create_service_specific_credential(
        UserName=user_name, ServiceName="bedrock.amazonaws.com", CredentialAgeDays=30
    )["ServiceSpecificCredential"]
    cred_id = created["ServiceSpecificCredentialId"]
    ctx.on_cleanup(
        lambda: _ignore_no_such_entity(
            lambda: iam.delete_service_specific_credential(
                UserName=user_name, ServiceSpecificCredentialId=cred_id
            )
        )
    )

    assert created["ServiceName"] == "bedrock.amazonaws.com", created["ServiceName"]
    assert created.get("ServiceCredentialSecret"), "the API-key secret must be disclosed on create"
    assert "ServicePassword" not in created, (
        f"the API-key shape must not carry ServicePassword, got keys {sorted(created)!r}"
    )
    assert "ServiceUserName" not in created, (
        f"the API-key shape must not carry ServiceUserName, got keys {sorted(created)!r}"
    )

    expected_alias = f"{user_name}-at-{ctx.account}"
    assert created.get("ServiceCredentialAlias") == expected_alias, (
        f"expected the alias to follow the password shape's '{{user}}-at-{{account}}' "
        f"convention, got {created.get('ServiceCredentialAlias')!r}"
    )

    created_at = created["CreateDate"]
    expires_at = created.get("ExpirationDate")
    assert expires_at is not None, "CredentialAgeDays must produce a parseable ExpirationDate"
    assert expires_at > created_at, (
        f"expected ExpirationDate {expires_at!r} after CreateDate {created_at!r}"
    )
    delta_days = (expires_at - created_at).days
    assert 29 <= delta_days <= 31, (
        f"expected ExpirationDate ~30 days after CreateDate (CredentialAgeDays=30), got a "
        f"{delta_days}-day delta"
    )

    listed = iam.list_service_specific_credentials(
        UserName=user_name, ServiceName="bedrock.amazonaws.com"
    )["ServiceSpecificCredentials"]
    match = next(c for c in listed if c["ServiceSpecificCredentialId"] == cred_id)
    assert "ServiceCredentialSecret" not in match, (
        f"the secret must not reappear on a later list read, got keys {sorted(match)!r}"
    )
    assert "ServicePassword" not in match, f"unexpected password field in {sorted(match)!r}"
    assert match["ServiceCredentialAlias"] == expected_alias, (
        f"expected the alias in the list read to match the one disclosed on create "
        f"({expected_alias!r}), got {match['ServiceCredentialAlias']!r}"
    )


def _ignore_no_such_entity(fn) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
