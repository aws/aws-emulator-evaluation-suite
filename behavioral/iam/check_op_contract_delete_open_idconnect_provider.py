"""op-contract-deleteOpenIDConnectProvider."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteOpenIDConnectProvider"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOpenIDConnectProvider removes the provider; NoSuchEntity on an unknown ARN."""
    iam = ctx.client("iam")

    host = ctx.unique_name("sim2real-behav-oidc-").lower().replace("_", "-")
    url = f"https://{host}.example.com"
    created = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=["0" * 40],
        ClientIDList=["sim2real-audience"],
    )
    arn = created["OpenIDConnectProviderArn"]

    # success path
    resp = iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from delete, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    code, message = _error(
        lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    )
    assert code == "NoSuchEntity", f"expected provider gone, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # error boundary: deleting the same (now-gone) ARN again, and a wholly bogus ARN
    code2, message2 = _error(
        lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    )
    assert code2 == "NoSuchEntity", f"expected NoSuchEntity, got {code2}"
    expected2 = f"OpenId connect Provider {arn} cannot be found."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"

    bogus_arn = arn.rsplit("/", 1)[0] + "/does-not-exist.example.com"
    code3, message3 = _error(
        lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=bogus_arn)
    )
    assert code3 == "NoSuchEntity", f"expected NoSuchEntity, got {code3}"
    expected3 = f"OpenId connect Provider {bogus_arn} cannot be found."
    assert message3 == expected3, f"expected message {expected3!r}, got {message3!r}"

    # the identifier is reusable: the same URL can be re-registered once the old
    # provider is gone
    recreated = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=["1" * 40],
        ClientIDList=["sim2real-audience-2"],
    )
    recreated_arn = recreated["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda a=recreated_arn: iam.delete_open_id_connect_provider(
            OpenIDConnectProviderArn=a
        )
    )
    assert recreated_arn == arn, (
        f"expected the same URL to yield the same provider ARN, got {recreated_arn}"
    )
    reread = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=recreated_arn)
    assert reread["ClientIDList"] == ["sim2real-audience-2"], (
        f"expected the re-created provider's own client IDs, got {reread['ClientIDList']}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
