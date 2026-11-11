"""public-access-block-absence-is-distinct-from-all-false."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "public-access-block-absence-is-distinct-from-all-false"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path", "resource:account-singleton:s3-account-public-access-block")
def run(ctx) -> None:
    """An all-false account PublicAccessBlock reads back as four falses, not as
    NoSuchPublicAccessBlockConfiguration, and a following Put replaces the record, not merges."""
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Bracket the mutation: whatever this account had, put it back.
    original = None
    try:
        original = s3c.get_public_access_block(AccountId=account)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
    ctx.on_cleanup(lambda: _restore_account_pab(s3c, account, original))

    all_false = {
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
    }
    got = _ensure_account_pab(s3c, account, all_false)
    assert got == all_false, (
        f"an all-false configuration read back as {got!r}; a target that normalises all-false "
        "to 'no configuration' answers NoSuchPublicAccessBlockConfiguration here instead"
    )

    mixed = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": False,
    }
    got = _ensure_account_pab(s3c, account, mixed)
    assert got == mixed, (
        f"a partial update read back as {got!r}, expected exactly {mixed!r} — Put replaces the "
        "whole configuration rather than merging into it"
    )
    assert got["IgnorePublicAcls"] is False and got["RestrictPublicBuckets"] is False, (
        f"the two flags left out of the second Put came back set: {got!r}"
    )


# ===== helpers =====

def _ensure_account_pab(s3c, account: str, config: dict, attempts: int = 25) -> dict:
    """Put the account-level PublicAccessBlock and wait until GET actually serves it.

    Writes to this record are eventually consistent and not linearizable: an earlier delete can
    land ~40s later and clobber this Put, so the Put is re-issued on divergence.
    """
    served = None
    for _ in range(attempts):
        s3c.put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=config)
        time.sleep(2)
        try:
            served = s3c.get_public_access_block(AccountId=account)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
                raise
            served = exc.response["Error"]["Code"]
            continue
        if served == config:
            return served
    raise AssertionError(
        f"the account-level PublicAccessBlock never converged on {config!r}; "
        f"the last read served {served!r}"
    )


def _restore_account_pab(s3c, account: str, original) -> None:
    """Return the account to the configuration it had before this check ran."""
    try:
        if original is None:
            s3c.delete_public_access_block(AccountId=account)
        else:
            s3c.put_public_access_block(
                AccountId=account, PublicAccessBlockConfiguration=original
            )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
