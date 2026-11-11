"""op-contract-create-account-alias."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-account-alias"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-account-alias")
def run(ctx) -> None:
    """CreateAccountAlias makes the alias the sole ListAccountAliases entry; a second distinct alias
    replaces it rather than raising LimitExceededException, and deleting the superseded alias
    raises NoSuchEntity with the exact message.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccountAlias.html
    """
    iam = ctx.client("iam")

    original = iam.list_account_aliases()["AccountAliases"]
    ctx.on_cleanup(lambda: _restore_aliases(iam, original))

    alias = _account_alias(ctx)
    iam.create_account_alias(AccountAlias=alias)
    ctx.on_cleanup(lambda: _best_effort_delete(iam, alias))

    aliases = iam.list_account_aliases()["AccountAliases"]
    assert aliases == [alias], f"expected [{alias!r}], got {aliases!r}"

    # Singleton replace, not rejection: a second, distinct CreateAccountAlias succeeds.
    second_alias = _account_alias(ctx, suffix="2")
    iam.create_account_alias(AccountAlias=second_alias)
    ctx.on_cleanup(lambda: _best_effort_delete(iam, second_alias))

    aliases = iam.list_account_aliases()["AccountAliases"]
    assert aliases == [second_alias], f"expected replace to [{second_alias!r}], got {aliases!r}"

    # The superseded alias is gone, not merely unlisted: an independent delete now rejects it.
    code, message = _error(lambda: iam.delete_account_alias(AccountAlias=alias))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for the superseded alias, got {code}"
    expected = f"The account alias {alias} cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _account_alias(ctx, suffix: str = "") -> str:
    raw = (ctx.unique_name("sim2real-iam-alias-") + suffix).lower()
    cleaned = re.sub(r"[^a-z0-9-]", "-", raw).strip("-")
    return cleaned or "sim2real-iam-alias"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _restore_aliases(iam, original: list) -> None:
    """Put the account alias slot back to the value it held before the check ran."""
    current = iam.list_account_aliases()["AccountAliases"]
    if current == original:
        return
    for alias in current:
        _best_effort_delete(iam, alias)
    for alias in original:
        iam.create_account_alias(AccountAlias=alias)


def _best_effort_delete(iam, alias: str) -> None:
    try:
        iam.delete_account_alias(AccountAlias=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
