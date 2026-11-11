"""create-open-id-connect-provider-duplicate-url-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-open-id-connect-provider-duplicate-url-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOpenIDConnectProvider rejects a second provider with the same issuer URL
    even when thumbprints/client IDs differ, with EntityAlreadyExists, and leaves the
    original provider's configuration untouched, while a distinct URL still succeeds."""
    iam = ctx.client("iam")
    thumbprint_a = "1" * 40
    thumbprint_b = "2" * 40
    resource_tags = [{"Key": "sim2real-managed", "Value": "true"}]

    url = f"https://{ctx.unique_name('sim2real-oidcdup-')}.example.com"
    resp = iam.create_open_id_connect_provider(
        Url=url, ThumbprintList=[thumbprint_a], ClientIDList=["client-x"], Tags=resource_tags
    )
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    code, message = _error(
        lambda: iam.create_open_id_connect_provider(
            Url=url, ThumbprintList=[thumbprint_b], ClientIDList=["client-y"]
        )
    )
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code!r}"
    assert message == f"Provider with url {url} already exists.", (
        f"duplicate-URL CreateOpenIDConnectProvider message: {message!r}"
    )

    # effect absent: no duplicate provider was created, and the original is unaffected
    providers = iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    matching_arns = [p["Arn"] for p in providers if p["Arn"] == arn]
    assert len(matching_arns) == 1, f"expected exactly 1 provider at {arn!r}, got {matching_arns!r}"

    current = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert current["ClientIDList"] == ["client-x"], (
        f"expected ClientIDList ['client-x'] unchanged, got {current['ClientIDList']!r}"
    )
    assert current["ThumbprintList"] == [thumbprint_a], (
        f"expected ThumbprintList [{thumbprint_a!r}] unchanged, got {current['ThumbprintList']!r}"
    )

    # positive control: a different URL succeeds without conflict
    url2 = f"https://{ctx.unique_name('sim2real-oidcdup2-')}.example.com"
    resp2 = iam.create_open_id_connect_provider(
        Url=url2, ThumbprintList=[thumbprint_a], Tags=resource_tags
    )
    arn2 = resp2["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn2))
    assert arn2 != arn, f"expected a distinct ARN for the second URL, got the same {arn2!r}"

    # terminal read, independent of the mutating call: the second provider actually exists
    # at the destination, distinct from the first, with none of this creating a third
    current2 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn2)
    assert current2["ThumbprintList"] == [thumbprint_a], (
        f"expected ThumbprintList [{thumbprint_a!r}] for the second provider, got "
        f"{current2['ThumbprintList']!r}"
    )
    providers_after = iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]
    all_arns = {p["Arn"] for p in providers_after}
    assert {arn, arn2} <= all_arns, f"expected both {arn!r} and {arn2!r} listed, got {all_arns!r}"
    matching_arns2 = [p["Arn"] for p in providers_after if p["Arn"] == arn2]
    assert len(matching_arns2) == 1, (
        f"expected exactly 1 provider at {arn2!r}, got {matching_arns2!r}"
    )


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
