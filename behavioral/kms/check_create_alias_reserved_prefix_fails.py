"""create-alias-reserved-prefix-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-alias-reserved-prefix-fails"
GROUP = 'aliases'
SERVICES = ['kms']
MSG_RESERVED = "The alias name for a customer managed CMK cannot begin with alias/aws/."


def _create_alias_error(fn):
    """Call fn(); return the botocore Error dict if it raises ClientError. An unexpected SUCCESS
    raises, because an emulator ACCEPTING an alias real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected CreateAlias to be refused, but it SUCCEEDED: {result!r}")


def _list_alias_names(kms):
    names = set()
    paginator = kms.get_paginator("list_aliases")
    for page in paginator.paginate():
        names.update(a["AliasName"] for a in page.get("Aliases", []))
    return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with a name under the reserved "alias/aws/" prefix fails with NotAuthorizedException and the
    exact message even for a customer key the caller owns, and the name is absent from ListAliases, while a
    regular alias on the same key succeeds and is listed."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        Description=ctx.unique_name("kms-aliasreserved-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # Positive control: an ordinary alias against this same, fully-permitted key succeeds --
    # proves the account/credentials are healthy for CreateAlias before the negative below is
    # trusted to mean anything.
    ok_alias = ctx.unique_name("alias/sim2real-behav-aliasreserved-ok-")
    kms.create_alias(AliasName=ok_alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=ok_alias: kms.delete_alias(AliasName=_a))

    reserved_alias = f"alias/aws/{ctx.unique_name('reserved-')}"
    error = _create_alias_error(
        lambda: kms.create_alias(AliasName=reserved_alias, TargetKeyId=key_id)
    )
    got = (error.get("Code"), error.get("Message"))
    expected = ("NotAuthorizedException", MSG_RESERVED)
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Effect absent, at an independent read: the refused alias never appears in the account's
    # alias catalogue, while the positive control's alias does.
    names = _list_alias_names(kms)
    assert reserved_alias not in names, (
        f"{reserved_alias} must not appear in ListAliases after a refused CreateAlias"
    )
    assert ok_alias in names, f"{ok_alias} (the positive control) must be visible in ListAliases"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
