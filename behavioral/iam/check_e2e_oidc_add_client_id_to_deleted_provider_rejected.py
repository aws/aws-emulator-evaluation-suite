"""e2e-oidc-add-client-id-to-deleted-provider-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-oidc-add-client-id-to-deleted-provider-rejected"
GROUP = "e2e"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddClientIDToOpenIDConnectProvider on a just-deleted provider's ARN is rejected NoSuchEntity
    and the provider stays gone, while the same call on a live sibling provider succeeds."""
    iam = ctx.client("iam")

    dead_url = f"https://{ctx.unique_name('sim2real-oidc-dead-')}.example.com"
    dead_arn = iam.create_open_id_connect_provider(
        Url=dead_url, ThumbprintList=["c" * 40], ClientIDList=["client-orig"]
    )["OpenIDConnectProviderArn"]
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=dead_arn)

    live_url = f"https://{ctx.unique_name('sim2real-oidc-live-')}.example.com"
    live_arn = iam.create_open_id_connect_provider(
        Url=live_url, ThumbprintList=["d" * 40], ClientIDList=["client-orig"]
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: _delete_provider_idempotent(iam, live_arn))

    expected_message = f"OpenIDConnect Provider not found for arn {dead_arn}"
    code, message = _error(
        lambda: iam.add_client_id_to_open_id_connect_provider(
            OpenIDConnectProviderArn=dead_arn, ClientID="client-new"
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity mutating a deleted OIDC provider, got {code!r}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_dead_code, still_dead_message = _error(
        lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=dead_arn)
    )
    assert still_dead_code == "NoSuchEntity", (
        f"deleted OIDC provider should remain gone after the rejected mutation, got {still_dead_code!r}"
    )
    assert still_dead_message == expected_message, (
        f"expected message {expected_message!r}, got {still_dead_message!r}"
    )

    # Positive control: the identical call against a live sibling provider succeeds
    # and the effect is observable.
    iam.add_client_id_to_open_id_connect_provider(
        OpenIDConnectProviderArn=live_arn, ClientID="client-new"
    )
    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=live_arn)
    assert set(got["ClientIDList"]) == {"client-orig", "client-new"}, (
        f"expected AddClientID to take effect on the live provider, got {got['ClientIDList']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so a target
    that accepts the rejected call cannot read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_provider_idempotent(iam, arn: str) -> None:
    try:
        iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
