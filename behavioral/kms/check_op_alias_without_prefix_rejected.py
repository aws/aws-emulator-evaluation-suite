"""op-alias-without-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-alias-without-prefix-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kms']


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _alias_names(kms, key_id):
    names = set()
    paginator = kms.get_paginator("list_aliases")
    for page in paginator.paginate(KeyId=key_id):
        names.update(a["AliasName"] for a in page["Aliases"])
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with a name missing the "alias/" prefix or containing disallowed characters fails with
    ValidationException and the exact message for each, none of those names appear in ListAliases, and a
    well-formed alias on the same key succeeds and is listed."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kms-op-aliasname-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-behavioral"}],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    good_alias = "alias/" + ctx.unique_name("sim2real-behav-kms-op-aliasname-")
    kms.create_alias(AliasName=good_alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=good_alias))
    assert good_alias in _alias_names(kms, key_id), (
        f"positive control: {good_alias!r} should be visible via ListAliases"
    )

    no_prefix = ctx.unique_name("sim2real-behav-noprefix-")  # missing the mandatory 'alias/' prefix
    bad_chars = "alias/" + ctx.unique_name("bad name!")      # illegal characters (space, '!')
    expected = {
        no_prefix: (
            'Alias must start with the prefix "alias/". Please see '
            "https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html"
        ),
        bad_chars: (
            f"1 validation error detected: Value '{bad_chars}' at 'aliasName' failed to satisfy "
            "constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9:/_-]+$"
        ),
    }
    bad_names = list(expected)
    for bad in bad_names:
        code, message = _error(
            lambda b=bad: kms.create_alias(AliasName=b, TargetKeyId=key_id)
        )
        assert code == "ValidationException", (
            f"{bad!r} -> expected ValidationException, got {code}"
        )
        assert message == expected[bad], f"{bad!r} -> unexpected message {message!r}"

    current = _alias_names(kms, key_id)
    for bad in bad_names:
        assert bad not in current, (
            f"effect absent: rejected alias {bad!r} must not appear in ListAliases"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
