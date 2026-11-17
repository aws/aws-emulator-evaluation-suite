"""tag-open-id-connect-provider-reserved-prefix-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "tag-open-id-connect-provider-reserved-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam", "cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagOpenIDConnectProvider rejects a tag key using the AWS-reserved 'aws:' prefix with
    InvalidInput, applies no tag, while a normal tag key on the same provider succeeds."""
    iam = ctx.client("iam")
    provider_arn = _create_provider(ctx, iam)

    # Break the precondition: tag key uses the reserved "aws:" prefix.
    bad_tags = [{"Key": "aws:reserved-marker", "Value": "should-not-apply"}]
    code, message = _error(
        lambda: iam.tag_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn, Tags=bad_tags)
    )
    assert code == "InvalidInput", f"expected InvalidInput, got {code}"
    expected = "Tag keys beginning with aws: are reserved for system use."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the reserved-prefix tag was not applied.
    after_reject = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=provider_arn)["Tags"]
    assert after_reject == [], (
        f"expected no tags applied after rejected TagOpenIDConnectProvider, got {after_reject}"
    )

    # Positive control: a normal tag key on the same provider succeeds.
    good_tags = [{"Key": "env", "Value": "test"}]
    iam.tag_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn, Tags=good_tags)
    listed = iam.list_open_id_connect_provider_tags(OpenIDConnectProviderArn=provider_arn)["Tags"]
    assert {(t["Key"], t["Value"]) for t in listed} == {(t["Key"], t["Value"]) for t in good_tags}, (
        f"expected tag {good_tags} to apply, got {listed}"
    )


def _create_provider(ctx, iam) -> str:
    """Create an OIDC provider on a Cognito user pool issuer this check owns, every target
    serves this issuer so no third-party identity provider is named or contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    issuer_url = f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    provider_arn = iam.create_open_id_connect_provider(Url=issuer_url)["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))
    return provider_arn


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a tag key with the 'aws:' prefix, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
