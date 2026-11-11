"""op-custom-key-store-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "op-custom-key-store-not-found-rejected"
GROUP = 'errors'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Custom key store operations on an unknown store id must fail with CustomKeyStoreNotFoundException."""
    kms = ctx.client("kms")
    bogus = "cks-1234567890abcdef0"

    # positive control: the DescribeCustomKeyStores surface itself is reachable and healthy for
    # this account, so a target that denies every custom-key-store call cannot pass merely by
    # returning CustomKeyStoreNotFoundException unconditionally.
    listing = kms.describe_custom_key_stores()
    assert "CustomKeyStores" in listing, f"DescribeCustomKeyStores (no filter) -> unexpected shape {listing!r}"

    # AWS sends each of these refusals with no message text.
    code, message = _error(lambda: kms.describe_custom_key_stores(CustomKeyStoreId=bogus))
    if code in ("UnsupportedOperationException", "NotSupported", "InvalidAction"):
        raise AssertionError(f"custom key store operations unavailable here ({code})")
    assert code == "CustomKeyStoreNotFoundException", f"DescribeCustomKeyStores -> got {code}"
    assert message == "", f"DescribeCustomKeyStores -> unexpected message {message!r}"

    code2, message2 = _error(lambda: kms.connect_custom_key_store(CustomKeyStoreId=bogus))
    assert code2 == "CustomKeyStoreNotFoundException", f"ConnectCustomKeyStore -> got {code2}"
    assert message2 == "", f"ConnectCustomKeyStore -> unexpected message {message2!r}"

    code3, message3 = _error(lambda: kms.disconnect_custom_key_store(CustomKeyStoreId=bogus))
    assert code3 == "CustomKeyStoreNotFoundException", f"DisconnectCustomKeyStore -> got {code3}"
    assert message3 == "", f"DisconnectCustomKeyStore -> unexpected message {message3!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
