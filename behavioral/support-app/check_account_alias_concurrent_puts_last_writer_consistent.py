"""account-alias-concurrent-puts-last-writer-consistent."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-alias-concurrent-puts-last-writer-consistent"
GROUP = "concurrency"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """Concurrent PutAccountAlias calls with distinct values leave GetAccountAlias equal to exactly one
    value a racer reported succeeding with, never a mix or an unattempted value."""
    client = ctx.client("support-app")

    original = client.get_account_alias().get("accountAlias")

    def _restore():
        if original:
            client.put_account_alias(accountAlias=original)
        else:
            _delete_alias_ignore_not_found(client)

    ctx.on_cleanup(_restore)

    racer_count = 8
    values = [f"sim2real-{i}-{uuid.uuid4().hex[:6]}" for i in range(racer_count)]

    def _put(value: str) -> str | None:
        try:
            client.put_account_alias(accountAlias=value)
            return value
        except ClientError:
            return None

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_put, v) for v in values]
        succeeded = {f.result() for f in as_completed(futures)}
    succeeded.discard(None)

    assert succeeded, "no racer succeeded"

    final = client.get_account_alias().get("accountAlias")
    assert final in values, f"final alias {final!r} was never one of the attempted values"
    assert final in succeeded, f"final alias {final!r} does not match any racer reported success"


def _delete_alias_ignore_not_found(client) -> None:
    try:
        client.delete_account_alias()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
