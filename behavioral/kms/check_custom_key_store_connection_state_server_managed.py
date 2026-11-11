"""custom-key-store-connection-state-server-managed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-key-store-connection-state-server-managed"
GROUP = "server-side"
SERVICES = ["kms"]
# AWS returns both not-found refusals with an empty message.
MSG_CLUSTER_NOT_FOUND = ""
MSG_STORE_NOT_FOUND = ""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomKeyStore on a well-formed but nonexistent CloudHSM cluster is rejected.

    The refusal is CloudHsmClusterNotFoundException, no key store record is left behind for the
    name, and an unrelated CreateKey succeeds as the control. ConnectionState is not exercised.
    """
    kms = ctx.client("kms")
    name = ctx.unique_name("sim2real-kms-cks-")
    # Syntactically valid per CloudHsmClusterId's ^cluster-[2-7a-zA-Z]{11,16}$ pattern, but
    # does not identify any real CloudHSM cluster in this account.
    bogus_cluster_id = "cluster-abcdefghijk"

    code = _err(
        lambda: kms.create_custom_key_store(
            CustomKeyStoreName=name,
            CloudHsmClusterId=bogus_cluster_id,
            TrustAnchorCertificate="-----BEGIN CERTIFICATE-----\nMIIBogus==\n-----END CERTIFICATE-----",
            KeyStorePassword="Sim2RealTestPassword1",
        )
    )
    expected = ("CloudHsmClusterNotFoundException", MSG_CLUSTER_NOT_FOUND)
    assert code == expected, f"expected {expected!r}, got {code!r}"

    # Effect absent: no orphaned custom key store record was materialized for the rejected call.
    lookup_code = _err(lambda: kms.describe_custom_key_stores(CustomKeyStoreName=name))
    expected = ("CustomKeyStoreNotFoundException", MSG_STORE_NOT_FOUND)
    assert lookup_code == expected, f"expected {expected!r}, got {lookup_code!r}"

    # Positive control: the KMS control plane itself is up and not just rejecting everything --
    # an ordinary, unrelated KMS control-plane call succeeds in the same account/region.
    control_key_id = kms.create_key(Description=ctx.unique_name("sim2real-kms-cks-control-"))[
        "KeyMetadata"
    ]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=control_key_id, PendingWindowInDays=7))
    control_state = kms.describe_key(KeyId=control_key_id)["KeyMetadata"]["KeyState"]
    assert control_state == "Enabled", control_state


def _err(fn):
    """Call fn(); return its (Code, Message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
