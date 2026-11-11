"""oidc-provider-add-client-id-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "oidc-provider-add-client-id-limit-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddClientIDToOpenIDConnectProvider fills the list to 100 client ids, fails on the
    101st with LimitExceeded and its exact message leaving 100, and accepts that id once
    another is removed."""
    iam = ctx.client("iam")
    thumbprint = "0" * 40

    url = f"https://{ctx.unique_name('sim2real-oidclim-')}.example.com"
    client_ids = [f"client-{i}" for i in range(99)]
    resp = iam.create_open_id_connect_provider(
        Url=url, ThumbprintList=[thumbprint], ClientIDList=client_ids
    )
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    # positive control: still one under the limit, the 100th client id is accepted
    iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID="client-99")
    at_limit = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert len(at_limit) == 100, f"expected 100 client ids after the positive control, got {len(at_limit)}"

    # break: the 101st client id is rejected
    code, message = _error(
        lambda: iam.add_client_id_to_open_id_connect_provider(
            OpenIDConnectProviderArn=arn, ClientID="client-100"
        )
    )
    assert code == "LimitExceeded", f"expected LimitExceeded, got {code!r}"
    expected = "Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: 100"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the 101st client id was not added
    current = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert "client-100" not in current, f"client-100 must not appear in {current}"
    assert len(current) == 100, f"expected the list to remain at 100, got {len(current)}"

    # restore: free a slot by removing an existing client id, then the identical call succeeds
    iam.remove_client_id_from_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID="client-0")
    iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID="client-100")
    restored = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert "client-100" in restored, f"expected client-100 in {restored} after restoring capacity"
    assert "client-0" not in restored, f"expected client-0 to remain removed, got {restored}"
    assert len(restored) == 100, f"expected the list back at 100, got {len(restored)}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
