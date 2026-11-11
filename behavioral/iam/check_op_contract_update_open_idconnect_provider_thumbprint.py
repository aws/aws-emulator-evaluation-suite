"""op-contract-updateOpenIDConnectProviderThumbprint."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-updateOpenIDConnectProviderThumbprint"
GROUP = "error-semantics"
SERVICES = ["iam"]

_INITIAL_THUMBPRINTS = ["a" * 40]
_UPDATED_THUMBPRINTS = ["b" * 40, "c" * 40]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOpenIDConnectProviderThumbprint: GetOpenIDConnectProvider reflects
    the full-replace semantics of the update, and a nonexistent provider ARN
    is rejected with NoSuchEntity."""
    iam = ctx.client("iam")
    url = f"https://{ctx.unique_name('sim2real-behav-oidc-')}.example.com"
    provider_arn = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=_INITIAL_THUMBPRINTS,
        ClientIDList=["sts.amazonaws.com"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    )

    before = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert before["ThumbprintList"] == _INITIAL_THUMBPRINTS, (
        f"expected initial thumbprint list {_INITIAL_THUMBPRINTS}, got {before['ThumbprintList']}"
    )

    # Success path: full replace of the thumbprint list (not a merge/append), order preserved
    # exactly as supplied.
    iam.update_open_id_connect_provider_thumbprint(
        OpenIDConnectProviderArn=provider_arn, ThumbprintList=_UPDATED_THUMBPRINTS
    )
    after = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    got = after["ThumbprintList"]
    assert got == _UPDATED_THUMBPRINTS, (
        f"expected full replace to {_UPDATED_THUMBPRINTS}, got {got}"
    )
    assert "a" * 40 not in got, "old thumbprint should not survive a full-replace update"

    # Error boundary: nonexistent OpenIDConnectProviderArn -> NoSuchEntityException
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_arn = f"arn:aws:iam::{account_id}:oidc-provider/does-not-exist.example.com"
    code, message = _error(
        lambda: iam.update_open_id_connect_provider_thumbprint(
            OpenIDConnectProviderArn=bogus_arn, ThumbprintList=_UPDATED_THUMBPRINTS
        )
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity for bogus provider ARN, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected update left nothing behind at that ARN either.
    get_code, get_message = _error(
        lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=bogus_arn)
    )
    assert get_code == "NoSuchEntity", (
        f"expected no provider to exist at the bogus ARN after the rejected update, got {get_code}"
    )
    expected_get = f"OpenIDConnect Provider not found for arn {bogus_arn}"
    assert get_message == expected_get, f"expected message {expected_get!r}, got {get_message!r}"


def _error(fn):
    """The captured AWS error (Code, Message)."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
