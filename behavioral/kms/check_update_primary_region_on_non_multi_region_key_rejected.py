"""update-primary-region-on-non-multi-region-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-primary-region-on-non-multi-region-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion rejects a single-Region key (UnsupportedOperationException), while a
    multi-Region primary with no replica there fails differently (ValidationException naming
    the missing replica); neither call changes the key."""
    kms = ctx.client("kms")

    # --- negative: ordinary key was never created with MultiRegion=True -----
    key = kms.create_key(Description=ctx.unique_name("sim2real-kms-not-mr-"))
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    assert key["KeyMetadata"]["MultiRegion"] is False, key["KeyMetadata"]

    # MultiRegion replication needs a genuinely distinct second AWS region; there is no
    # account-derived way to pick one, so this falls back between two fixed regions.
    other_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    code_ordinary, _msg_ordinary = _error_code_and_message(
        lambda: kms.update_primary_region(KeyId=key_id, PrimaryRegion=other_region)
    )
    assert code_ordinary == "UnsupportedOperationException", (
        f"expected UnsupportedOperationException for a non-multi-Region key, "
        f"got {code_ordinary!r} ({_msg_ordinary!r})"
    )
    assert _msg_ordinary == f"{key['KeyMetadata']['Arn']} is not a multi-region key.", (
        _msg_ordinary
    )

    unchanged = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert unchanged["MultiRegion"] is False, (
        f"expected MultiRegion still False after the rejected call, got {unchanged!r}"
    )
    assert unchanged["KeyState"] == "Enabled", (
        f"expected KeyState still Enabled after the rejected call, got {unchanged!r}"
    )

    # --- positive control: a multi-Region primary key with no replica yet --------
    # A different error here shows the rejection above is tied to MultiRegion status.
    primary = kms.create_key(
        MultiRegion=True, Description=ctx.unique_name("sim2real-kms-mr-primary-")
    )
    primary_id = primary["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=primary_id, PendingWindowInDays=7))
    assert primary["KeyMetadata"]["MultiRegion"] is True, primary["KeyMetadata"]

    code_mr_no_replica, msg_mr_no_replica = _error_code_and_message(
        lambda: kms.update_primary_region(KeyId=primary_id, PrimaryRegion=other_region)
    )
    # A multi-Region primary with no replica in the target region gets ValidationException.
    assert code_mr_no_replica == "ValidationException", (
        f"expected ValidationException for a multi-Region primary key with no replica "
        f"in {other_region!r}, got {code_mr_no_replica!r} ({msg_mr_no_replica!r})"
    )
    assert msg_mr_no_replica == (
        f"{primary_id} does not have a replica key in the specified Region."
    ), f"expected the ValidationException message to name the missing replica, got {msg_mr_no_replica!r}"
    assert code_mr_no_replica != code_ordinary, (
        f"expected a distinct error code from the ordinary-key case ({code_ordinary!r}), "
        f"got {code_mr_no_replica!r}"
    )

    # effect-absent: an independent read shows the primary key untouched -- still
    # PRIMARY, still rooted in ctx.region, still no replicas.
    still_primary = kms.describe_key(KeyId=primary_id)["KeyMetadata"]
    assert still_primary["MultiRegion"] is True, still_primary
    assert still_primary["KeyState"] == "Enabled", still_primary
    mrc = still_primary["MultiRegionConfiguration"]
    assert mrc["MultiRegionKeyType"] == "PRIMARY", mrc
    assert mrc["PrimaryKey"]["Region"] == ctx.region, (
        f"expected the primary key's own region to remain {ctx.region!r} after the "
        f"rejected UpdatePrimaryRegion call, got {mrc!r}"
    )
    assert mrc["ReplicaKeys"] == [], (
        f"expected no replicas to have been created by the rejected call, got {mrc!r}"
    )



def _error_code_and_message(fn):
    """Return fn()'s error (Code, Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
