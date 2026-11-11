"""describe-custom-key-stores-shape."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-custom-key-stores-shape"
GROUP = 'key_metadata'
SERVICES = ['kms']


def _error(fn):
    """Return the botocore Error dict fn() raises. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCustomKeyStores returns a well-formed (possibly empty) list; passing both
    CustomKeyStoreId and CustomKeyStoreName fails ValidationException, and an unissued Marker
    fails InvalidMarkerException."""
    kms = ctx.client("kms")
    try:
        resp = kms.describe_custom_key_stores()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("UnsupportedOperationException", "NotSupported", "InvalidAction"):
            raise AssertionError(f"DescribeCustomKeyStores unavailable here ({code})")
        raise
    stores = resp["CustomKeyStores"]
    assert isinstance(stores, list), type(stores)
    for store in stores:
        assert "CustomKeyStoreId" in store, store
        assert "CustomKeyStoreName" in store, store
        assert "ConnectionState" in store, store

    both = _error(
        lambda: kms.describe_custom_key_stores(
            CustomKeyStoreId="cks-1234567890abcdef0",
            CustomKeyStoreName=ctx.unique_name("sim2real-cks-shape-"),
        )
    )
    assert both.get("Code") == "ValidationException", f"CustomKeyStoreId+CustomKeyStoreName -> got {both}"
    # AWS returns this refusal with an empty message.
    assert both.get("Message") == "", f"CustomKeyStoreId+CustomKeyStoreName -> got {both}"

    marker = _error(lambda: kms.describe_custom_key_stores(Marker="not-a-real-marker"))
    assert marker.get("Code") == "InvalidMarkerException", f"bogus Marker -> got {marker}"
    assert marker.get("Message") == "", f"bogus Marker -> got {marker}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
