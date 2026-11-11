"""update-custom-key-store-reconfigures-cluster."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-custom-key-store-reconfigures-cluster"
GROUP = "error-semantics"
SERVICES = ["kms"]

#: Well-formed custom key store id (cks- + 16 hex) that was never created.
_ABSENT_CKS_ID = "cks-0000000000000000d"
#: Same parameter, a value that is not a custom key store id at all.
_MALFORMED_CKS_ID = "not-a-cks"
_XKS_UNREACHABLE_MSG = (
    "AWS KMS cannot communicate with the external key store proxy. This might be a transient "
    "network issue. If you see this error repeatedly, verify that your external key store proxy "
    "is active and is connected to the network, and that its endpoint URI is correct in your "
    "external key store."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCustomKeyStore rejects absent and unparseable ids with CustomKeyStoreNotFoundException.

    DescribeCustomKeyStores agrees and no store appears. CreateCustomKeyStore for an external key
    store with an unreachable proxy URI fails with XksProxyUriUnreachableException. Codes and messages.
    """
    kms = ctx.client("kms")

    absent, absent_msg = _error(
        lambda: kms.update_custom_key_store(
            CustomKeyStoreId=_ABSENT_CKS_ID,
            NewCustomKeyStoreName=ctx.unique_name("sim2real-cks-upd-"),
        )
    )
    assert absent == "CustomKeyStoreNotFoundException", (
        f"expected CustomKeyStoreNotFoundException for an absent key store id, got {absent!r}"
    )
    assert absent_msg == "", f"expected an empty message, got {absent_msg!r}"

    malformed, malformed_msg = _error(
        lambda: kms.update_custom_key_store(
            CustomKeyStoreId=_MALFORMED_CKS_ID,
            NewCustomKeyStoreName=ctx.unique_name("sim2real-cks-upd-"),
        )
    )
    assert malformed == "CustomKeyStoreNotFoundException", (
        f"expected an unparseable key store id to collapse onto "
        f"CustomKeyStoreNotFoundException too, got {malformed!r}"
    )
    assert malformed_msg == "", f"expected an empty message, got {malformed_msg!r}"

    described, described_msg = _error(
        lambda: kms.describe_custom_key_stores(CustomKeyStoreId=_ABSENT_CKS_ID)
    )
    assert described == "CustomKeyStoreNotFoundException", (
        f"expected the read path to agree the key store is absent, got {described!r}"
    )
    assert described_msg == "", f"expected an empty message, got {described_msg!r}"

    # Effect absent: neither rejected update brought a key store into existence.
    listed = kms.describe_custom_key_stores()["CustomKeyStores"]
    assert all(s["CustomKeyStoreId"] != _ABSENT_CKS_ID for s in listed), listed

    # CreateCustomKeyStore for an external key store reaches out to the proxy during the call.
    unreachable, unreachable_msg = _error(
        lambda: kms.create_custom_key_store(
            CustomKeyStoreName=ctx.unique_name("sim2real-cks-xks-"),
            CustomKeyStoreType="EXTERNAL_KEY_STORE",
            XksProxyUriEndpoint="https://xks.sim2real.example.com",
            XksProxyUriPath="/kms/xks/v1",
            XksProxyConnectivity="PUBLIC_ENDPOINT",
            XksProxyAuthenticationCredential={
                # Shapes are enforced before the proxy is contacted: AccessKeyId is base32
                # (^[A-Z2-7]+$, 20-30) and RawSecretAccessKey base64 (43-64).
                "AccessKeyId": "SIM2REALPROBEXKSAKID2ABC",
                "RawSecretAccessKey": "c2ltMnJlYWxwcm9iZXNlY3JldGtleWZvcnhrc3Rlc3RpbmcxMjM0",
            },
        )
    )
    assert unreachable == "XksProxyUriUnreachableException", (
        f"expected CreateCustomKeyStore to test the XKS proxy synchronously and fail with "
        f"XksProxyUriUnreachableException, got {unreachable!r}"
    )
    assert unreachable_msg == _XKS_UNREACHABLE_MSG, unreachable_msg


def _error(fn):
    """Return (code, message) of the ClientError fn raises; a success is a mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("expected the call to be refused, it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
