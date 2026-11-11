"""account-alias-length-exceeded-invalid."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-alias-length-exceeded-invalid"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """PutAccountAlias rejects a value longer than the documented 30-character
    maximum with ValidationException, leaves the prior value untouched, and a
    valid-length Put still succeeds in the same run."""
    client = ctx.client("support-app")

    original = client.get_account_alias().get("accountAlias")

    def _restore():
        if original:
            client.put_account_alias(accountAlias=original)
        else:
            _delete_alias_ignore_not_found(client)

    ctx.on_cleanup(_restore)

    baseline = f"sim2real-{uuid.uuid4().hex[:10]}"
    client.put_account_alias(accountAlias=baseline)
    assert client.get_account_alias().get("accountAlias") == baseline

    too_long = "a" * 31
    assert len(too_long) > 30
    code, message = _error(lambda: client.put_account_alias(accountAlias=too_long))
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        f"1 validation error detected: Value '{too_long}' at 'accountAlias' failed to satisfy "
        "constraint: Member must have length less than or equal to 30"
    ), message

    got = client.get_account_alias().get("accountAlias")
    assert got == baseline, f"oversized Put mutated state; expected {baseline!r}, got {got!r}"

    good_value = f"sim2real-{uuid.uuid4().hex[:10]}"
    client.put_account_alias(accountAlias=good_value)
    assert client.get_account_alias().get("accountAlias") == good_value


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_alias_ignore_not_found(client) -> None:
    try:
        client.delete_account_alias()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
