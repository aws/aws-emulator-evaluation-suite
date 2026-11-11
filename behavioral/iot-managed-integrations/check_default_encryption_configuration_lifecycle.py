"""default-encryption-configuration-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "default-encryption-configuration-lifecycle"
GROUP = "crud-depth"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDefaultEncryptionConfiguration rejects CUSTOMER_KEY_ENCRYPTION without a kmsKeyArn;
    MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION is accepted and GetDefaultEncryptionConfiguration
    reflects it (positive control), restoring whatever configuration existed beforehand."""
    iot = _iot_client(ctx)

    original = _get_current(iot)
    if original is not None:
        def _restore():
            kwargs = {"encryptionType": original["encryptionType"]}
            if original.get("kmsKeyArn"):
                kwargs["kmsKeyArn"] = original["kmsKeyArn"]
            iot.put_default_encryption_configuration(**kwargs)

        ctx.on_cleanup(_restore)

    code, code_msg = _error(
        lambda: iot.put_default_encryption_configuration(encryptionType="CUSTOMER_KEY_ENCRYPTION")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert code_msg == 'IoT Managed Integrations is not authorized to use the key.', code_msg

    put_resp = iot.put_default_encryption_configuration(
        encryptionType="MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION"
    )
    assert put_resp["encryptionType"] == "MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION", (
        f"expected MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION, got {put_resp.get('encryptionType')!r}"
    )

    got = iot.get_default_encryption_configuration()
    assert got["encryptionType"] == "MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION", (
        f"expected MANAGED_INTEGRATIONS_DEFAULT_ENCRYPTION, got {got.get('encryptionType')!r}"
    )
    state = got["configurationStatus"]["state"]
    assert state != "UPDATE_FAILED", f"put succeeded but configurationStatus.state is {state!r}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so we pin this
    # client to a supported region via ctx.client's region override, which keeps
    # the leased/emulator credential and endpoint wiring intact on both transports.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _get_current(iot):
    try:
        return iot.get_default_encryption_configuration()
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
