"""account-alias-delete-clears-state."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "account-alias-delete-clears-state"
GROUP = "state"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """DeleteAccountAlias transitions the singleton alias from 'set' to 'unset':
    after deletion, GetAccountAlias no longer returns the deleted value."""
    client = ctx.client("support-app")

    original = client.get_account_alias().get("accountAlias")

    def _restore():
        if original:
            client.put_account_alias(accountAlias=original)
        else:
            _delete_alias_ignore_not_found(client)

    ctx.on_cleanup(_restore)

    value = f"sim2real-{uuid.uuid4().hex[:10]}"
    client.put_account_alias(accountAlias=value)
    put = client.get_account_alias().get("accountAlias")
    assert put == value, f"expected accountAlias={value!r} after put, got {put!r}"

    client.delete_account_alias()

    got = client.get_account_alias().get("accountAlias")
    assert got != value, "accountAlias still reflects the deleted value"
    assert not got, f"expected unset accountAlias after delete, got {got!r}"


def _delete_alias_ignore_not_found(client) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_account_alias()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
