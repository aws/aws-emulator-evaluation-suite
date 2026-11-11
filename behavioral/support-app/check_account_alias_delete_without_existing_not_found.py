"""account-alias-delete-without-existing-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-alias-delete-without-existing-not-found"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """DeleteAccountAlias on an account with no alias set is rejected with
    ResourceNotFoundException, and a positive control (put/get/delete on an
    alias that DOES exist) still succeeds in the same run."""
    client = ctx.client("support-app")

    original = client.get_account_alias().get("accountAlias")

    def _restore():
        if original:
            client.put_account_alias(accountAlias=original)
        else:
            _delete_alias_ignore_not_found(client)

    ctx.on_cleanup(_restore)

    # Force the "unset" precondition.
    _delete_alias_ignore_not_found(client)
    precondition = client.get_account_alias().get("accountAlias")
    assert not precondition, f"expected unset accountAlias precondition, got {precondition!r}"

    code, message = _error(lambda: client.delete_account_alias())
    assert code == "ResourceNotFoundException", f"unexpected code: {code}: {message}"
    assert message == f"Account alias for account {ctx.account} not found", message

    # Effect absent: still unset after the rejected delete.
    after_reject = client.get_account_alias().get("accountAlias")
    assert not after_reject, f"expected unset accountAlias after rejected delete, got {after_reject!r}"

    # Positive control: the same operation succeeds once an alias actually exists.
    value = f"sim2real-{uuid.uuid4().hex[:10]}"
    client.put_account_alias(accountAlias=value)
    got = client.get_account_alias().get("accountAlias")
    assert got == value, f"expected accountAlias {value!r}, got {got!r}"
    client.delete_account_alias()
    after_delete = client.get_account_alias().get("accountAlias")
    assert not after_delete, f"expected unset accountAlias after delete, got {after_delete!r}"


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
