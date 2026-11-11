"""account-alias-invalid-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-alias-invalid-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:support-app-account-alias")
def run(ctx) -> None:
    """PutAccountAlias rejects a value containing characters outside
    ^[\\w\\- ]+$ (e.g. '!') with ValidationException, the previously-set
    alias is left untouched, and a valid Put still succeeds in the same run."""
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
    got_baseline = client.get_account_alias().get("accountAlias")
    assert got_baseline == baseline, f"positive control failed to persist; expected {baseline!r}, got {got_baseline!r}"

    bad_value = "bad!alias#" + uuid.uuid4().hex[:6]
    code, message = _error(lambda: client.put_account_alias(accountAlias=bad_value))
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        f"1 validation error detected: Value '{bad_value}' at 'accountAlias' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w\\- ]+"
    ), message

    # Effect absent: the rejected value never overwrote the baseline.
    got = client.get_account_alias().get("accountAlias")
    assert got == baseline, f"invalid Put mutated state; expected {baseline!r}, got {got!r}"

    # Positive control: a well-formed value still succeeds.
    good_value = f"sim2real-{uuid.uuid4().hex[:10]}"
    client.put_account_alias(accountAlias=good_value)
    got_good = client.get_account_alias().get("accountAlias")
    assert got_good == good_value, f"well-formed Put after rejection did not take effect; expected {good_value!r}, got {got_good!r}"


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
