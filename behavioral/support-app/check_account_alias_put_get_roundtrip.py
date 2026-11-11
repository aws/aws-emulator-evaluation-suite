"""account-alias-put-get-roundtrip."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "account-alias-put-get-roundtrip"
GROUP = "state"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """PutAccountAlias followed by GetAccountAlias returns the exact value written."""
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

    got = client.get_account_alias().get("accountAlias")
    assert got == value, f"expected accountAlias={value!r}, got {got!r}"


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
