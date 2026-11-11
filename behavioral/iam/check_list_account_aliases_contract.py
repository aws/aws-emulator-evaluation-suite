"""list-account-aliases-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-account-aliases-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:iam-account-alias")
def run(ctx) -> None:
    """ListAccountAliases lists the created alias, and a second distinct CreateAccountAlias
    replaces the account's single alias slot instead of raising LimitExceededException.

    Reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccountAliases.html
    """
    iam = ctx.client("iam")

    existing = iam.list_account_aliases()["AccountAliases"]

    if existing:
        # The account already has an alias: swap to a throwaway alias and restore the
        # original immediately, so account state ends up unchanged.
        alias = existing[0]
        pre_check = iam.list_account_aliases()["AccountAliases"]
        assert alias in pre_check, f"expected pre-existing alias {alias!r} in {pre_check!r}"

        swap_alias = ctx.unique_name("sim2real-alias-")
        iam.create_account_alias(AccountAlias=swap_alias)
        ctx.on_cleanup(lambda: iam.create_account_alias(AccountAlias=alias))
        assert iam.list_account_aliases()["AccountAliases"] == [swap_alias], (
            "CreateAccountAlias must replace the existing alias in place, not add to it"
        )

        iam.create_account_alias(AccountAlias=alias)
        assert iam.list_account_aliases()["AccountAliases"] == [alias], "original alias must be restored after swap"
        return

    alias = ctx.unique_name("sim2real-alias-")
    iam.create_account_alias(AccountAlias=alias)
    ctx.on_cleanup(lambda: _safe_delete_alias(iam, alias))

    resp = iam.list_account_aliases()
    assert alias in resp["AccountAliases"], "created alias missing from ListAccountAliases"

    # An account has at most one alias; a second distinct name replaces it in place.
    alias2 = ctx.unique_name("sim2real-alias2-")
    iam.create_account_alias(AccountAlias=alias2)
    ctx.on_cleanup(lambda: _safe_delete_alias(iam, alias2))
    assert iam.list_account_aliases()["AccountAliases"] == [alias2], "second CreateAccountAlias must replace the first alias"


def _safe_delete_alias(iam, alias):
    from botocore.exceptions import ClientError

    try:
        iam.delete_account_alias(AccountAlias=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
