"""runtime-log-configuration-put-get-reset-cycle."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "runtime-log-configuration-put-get-reset-cycle"
GROUP = "state-machine"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Runtime-log put/get/reset: a missing thing is ResourceNotFoundException and stores nothing.

    On an existing thing the put is ValidationException ("Only 1P device or hub is supported for
    Runtime logging") yet the configuration persists, and Reset removes it again."""
    iot = _iot_client(ctx)

    missing_code, missing_message = _error_code(
        lambda: iot.put_runtime_log_configuration(
            ManagedThingId="sim2real-bogus-managed-thing-id",
            RuntimeLogConfigurations={"LogLevel": "INFO"},
        )
    )
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a managed thing id that does not exist, "
        f"got {missing_code!r}"
    )
    assert missing_message == "The runtime log configuration is for a managed thing resource that cannot be found.", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {missing_message!r}"
    )

    thing_id = _create_thing(ctx, iot)

    # positive control: this id really does resolve, so the rejection below is about the
    # device class and not about a missing resource.
    existing = iot.get_managed_thing(Identifier=thing_id)
    assert existing["Id"] == thing_id, (
        f"expected GetManagedThing to resolve {thing_id!r}, got {existing.get('Id')!r}"
    )

    before_code, before_message = _error_code(lambda: iot.get_runtime_log_configuration(ManagedThingId=thing_id))
    assert before_code == "ResourceNotFoundException", (
        f"expected no runtime log configuration on a freshly created managed thing, got {before_code!r}"
    )
    assert before_message == "Runtime log configuration for the requested managedThingId doesn't exist", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {before_message!r}"
    )

    unsupported_code, unsupported_message = _error_code(
        lambda: iot.put_runtime_log_configuration(
            ManagedThingId=thing_id,
            RuntimeLogConfigurations={"LogLevel": "DEBUG", "UploadLog": True},
        )
    )
    assert unsupported_code == "ValidationException", (
        f"expected ValidationException (runtime logging is 1P-only) for a third-party managed "
        f"thing, got {unsupported_code!r}"
    )
    assert unsupported_message == "Only 1P device or hub is supported for Runtime logging", (
        f"expected the exact ValidationException message AWS returns, got {unsupported_message!r}"
    )

    # The rejection is NOT atomic: the configuration is stored regardless. Read it at the
    # destination rather than from the (errored) put response.
    got = iot.get_runtime_log_configuration(ManagedThingId=thing_id)
    assert got["ManagedThingId"] == thing_id, (
        f"expected the stored configuration to belong to {thing_id!r}, got {got.get('ManagedThingId')!r}"
    )
    log_level = got["RuntimeLogConfigurations"]["LogLevel"]
    assert log_level == "DEBUG", (
        f"expected the rejected put to have stored LogLevel 'DEBUG' anyway, got {log_level!r}"
    )
    upload_log = got["RuntimeLogConfigurations"]["UploadLog"]
    assert upload_log is True, (
        f"expected the rejected put to have stored UploadLog True anyway, got {upload_log!r}"
    )

    # Reset clears it: the stored-despite-rejection configuration is reversible.
    iot.reset_runtime_log_configuration(ManagedThingId=thing_id)
    after_code, after_message = _error_code(lambda: iot.get_runtime_log_configuration(ManagedThingId=thing_id))
    assert after_code == "ResourceNotFoundException", (
        f"expected ResetRuntimeLogConfiguration to clear the configuration, got {after_code!r}"
    )
    assert after_message == "Runtime log configuration for the requested managedThingId doesn't exist", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {after_message!r}"
    )


def _wifi_barcode() -> str:
    # The only AuthenticationMaterial real AWS accepts on CreateManagedThing is the
    # WIFI_SETUP_QR_BAR_CODE envelope "UPC:<valid UPC-A>;SN:<12-digit serial>" -- an
    # opaque random string with AuthenticationMaterialType="DISCOVERED_DEVICE" is rejected
    # with ValidationException.
    return f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_thing(ctx, iot) -> str:
    resp = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        Tags={"env": "sim2real"},
    )
    thing_id = resp["Id"]

    def _cleanup():
        try:
            iot.delete_managed_thing(Identifier=thing_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return thing_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
