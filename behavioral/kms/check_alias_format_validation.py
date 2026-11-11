"""alias-format-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-format-validation"
GROUP = 'aliases'
SERVICES = ['kms']
MSG_NO_PREFIX = (
    'Alias must start with the prefix "alias/". '
    "Please see https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html"
)

def _err(fn):
    """Return (Code, Message) of the ClientError fn() raises; raise on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected ClientError, call succeeded with {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAlias with invalid format (missing alias/ prefix) is rejected with the specific
    ValidationException, while a well-formed alias for the same key is unaffected."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-alias-format-validation"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    # Positive control: a well-formed alias for the same key succeeds, proving the
    # account/credentials are otherwise healthy for CreateAlias.
    good_alias = ctx.unique_name("alias/sim2real-behav-goodalias-")
    kms.create_alias(AliasName=good_alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=good_alias: kms.delete_alias(AliasName=_a))

    # Negative: alias name missing the mandatory "alias/" prefix is rejected with the
    # specific error, not merely "some error".
    bad_alias = ctx.unique_name("sim2real-behav-noprefix-")
    got = _err(
        lambda: kms.create_alias(AliasName=bad_alias, TargetKeyId=key_id)
    )
    expected = ("ValidationException", MSG_NO_PREFIX)
    assert got == expected, f"expected {expected!r}, got {got!r}"

    # Terminal read: independent of both create_alias calls above. The good alias is
    # visible, the rejected one never came into existence.
    # ListAliases is eventually consistent, so poll (bounded) until the good alias is listed.
    deadline = time.monotonic() + 60
    names = set()
    while time.monotonic() < deadline:
        names = {a["AliasName"] for a in kms.list_aliases(KeyId=key_id).get("Aliases", [])}
        if good_alias in names:
            break
        time.sleep(2)
    assert good_alias in names, f"expected {good_alias!r} in {names}"
    assert bad_alias not in names, f"expected {bad_alias!r} not in {names}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
