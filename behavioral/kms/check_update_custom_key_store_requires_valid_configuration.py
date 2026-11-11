"""update-custom-key-store-requires-valid-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-custom-key-store-requires-valid-configuration"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCustomKeyStore on a well-formed but non-existent custom key store id is refused with
    CustomKeyStoreNotFoundException, and DescribeCustomKeyStores confirms the id is unknown.
    """
    kms = ctx.client("kms")

    bogus_id = ctx.unique_name("sim2real-cks-")[:64]
    # KMS sends CustomKeyStoreNotFoundException with no message at all.
    err = _error(
        lambda: kms.update_custom_key_store(
            CustomKeyStoreId=bogus_id, NewCustomKeyStoreName=ctx.unique_name("sim2real-cks-name-")
        )
    )
    assert err["Code"] == "CustomKeyStoreNotFoundException", err
    assert err["Message"] == "", err

    describe_err = _error(
        lambda: kms.describe_custom_key_stores(CustomKeyStoreId=bogus_id)
    )
    assert describe_err["Code"] == "CustomKeyStoreNotFoundException", describe_err
    assert describe_err["Message"] == "", describe_err


def _error(fn):
    """Return the Code and Message of the expected ClientError; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
