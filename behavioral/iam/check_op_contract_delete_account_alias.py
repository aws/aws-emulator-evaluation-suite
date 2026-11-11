"""op-contract-deleteAccountAlias."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteAccountAlias"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-account-alias")
def run(ctx) -> None:
    """DeleteAccountAlias clears the account alias; NoSuchEntity when the named alias isn't set."""
    iam = ctx.client("iam")

    # The alias slot is an account singleton: snapshot it and restore the original on cleanup.
    original = iam.list_account_aliases()["AccountAliases"]
    alias = ctx.unique_name("sim2real-behav-alias-").lower().replace("_", "-")
    ctx.on_cleanup(lambda: _restore_alias(iam, original, alias))

    iam.create_account_alias(AccountAlias=alias)

    # success path: delete and confirm it's gone
    resp = iam.delete_account_alias(AccountAlias=alias)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert iam.list_account_aliases()["AccountAliases"] == []

    # error boundary: deleting an alias that was never set on the account -> NoSuchEntityException
    bogus = ctx.unique_name("sim2real-behav-noalias-").lower().replace("_", "-")
    code, message = _error(lambda: iam.delete_account_alias(AccountAlias=bogus))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"The account alias {bogus} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _restore_alias(iam, original: list, ours: str) -> None:
    """Put the account alias slot back to the snapshot taken before the check wrote it."""
    current = iam.list_account_aliases()["AccountAliases"]
    if original:
        if current != original:
            iam.create_account_alias(AccountAlias=original[0])
    elif ours in current:
        iam.delete_account_alias(AccountAlias=ours)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
