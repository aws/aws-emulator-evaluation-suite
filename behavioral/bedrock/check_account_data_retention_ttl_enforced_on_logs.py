"""account-data-retention-ttl-enforced-on-logs."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-data-retention-ttl-enforced-on-logs"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:bedrock-account-data-retention")
def run(ctx) -> None:
    """Put/GetAccountDataRetention round-trip the mode exactly; an out-of-enum mode is rejected
    with ValidationException without overwriting the stored mode."""
    bedrock = ctx.client("bedrock")

    original_mode = bedrock.get_account_data_retention()["mode"]
    ctx.on_cleanup(lambda: bedrock.put_account_data_retention(mode=original_mode))

    target_mode = "none" if original_mode != "none" else "default"
    put_resp = bedrock.put_account_data_retention(mode=target_mode)
    assert put_resp["mode"] == target_mode, (
        f"expected PutAccountDataRetention to echo the requested mode={target_mode!r}; "
        f"got {put_resp['mode']!r}"
    )

    fetched = bedrock.get_account_data_retention()
    assert fetched["mode"] == target_mode, (
        f"expected GetAccountDataRetention to reflect the just-set mode={target_mode!r} "
        f"on an independent read; got {fetched['mode']!r}"
    )

    other_mode = "provider_data_share" if target_mode != "provider_data_share" else "inherit"
    bedrock.put_account_data_retention(mode=other_mode)
    reflected = bedrock.get_account_data_retention()["mode"]
    assert reflected == other_mode, (
        f"expected the second write to persist mode={other_mode!r}; got {reflected!r}"
    )

    try:
        bedrock.put_account_data_retention(mode="totally-bogus-retention-mode")
        raise AssertionError("expected ValidationException for an out-of-enum retention mode")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", (
            f"expected ValidationException for a bogus mode, got {err.response['Error']['Code']!r}"
        )
        expected_message = (
            "1 validation error detected: Value at 'mode' failed to satisfy constraint: "
            "Member must satisfy enum value set: [default, provider_data_share, none, aws_review, inherit]"
        )
        assert err.response["Error"]["Message"] == expected_message, (
            f"expected message {expected_message!r}, got {err.response['Error']['Message']!r}"
        )

    # The invalid attempt must not have overwritten the previously-set valid mode.
    unchanged = bedrock.get_account_data_retention()["mode"]
    assert unchanged == other_mode, (
        f"expected the rejected bogus-mode write to leave mode={other_mode!r} untouched; "
        f"got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
