"""account-alias-upsert-overwrites-previous-value."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "account-alias-upsert-overwrites-previous-value"
GROUP = "state"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """PutAccountAlias is an idempotent upsert: a second Put with a new value fully
    replaces the first -- Get reflects only the latest value, never the prior one."""
    client = ctx.client("support-app")

    original = client.get_account_alias().get("accountAlias")

    def _restore():
        if original:
            client.put_account_alias(accountAlias=original)
        else:
            _delete_alias_ignore_not_found(client)

    ctx.on_cleanup(_restore)

    first = f"sim2real-{uuid.uuid4().hex[:10]}"
    second = f"sim2real-{uuid.uuid4().hex[:10]}"

    client.put_account_alias(accountAlias=first)
    after_first = client.get_account_alias().get("accountAlias")
    assert after_first == first, f"expected accountAlias={first!r} after first put, got {after_first!r}"

    client.put_account_alias(accountAlias=second)
    got = client.get_account_alias().get("accountAlias")
    assert got == second, f"expected overwritten accountAlias={second!r}, got {got!r}"
    assert got != first, f"stale value {first!r} still visible after overwrite with {second!r}"


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
