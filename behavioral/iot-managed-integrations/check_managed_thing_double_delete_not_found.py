"""managed-thing-double-delete-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-thing-double-delete-not-found"
GROUP = "error-semantics"
SERVICES = ["iot-managed-integrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an already-deleted managed thing raises ResourceNotFoundException; a fresh
    create/delete cycle (the positive control) is unaffected."""
    iot = _iot_client(ctx)

    thing_id = _create_thing(ctx, iot)
    iot.delete_managed_thing(Identifier=thing_id)
    first_get_code, first_get_code_msg = _error(lambda: iot.get_managed_thing(Identifier=thing_id))
    assert first_get_code == "ResourceNotFoundException", first_get_code
    assert first_get_code_msg == 'Managed Thing resource not found.', first_get_code_msg

    second_delete_code, second_delete_code_msg = _error(lambda: iot.delete_managed_thing(Identifier=thing_id))
    assert second_delete_code == "ResourceNotFoundException", second_delete_code
    assert second_delete_code_msg == f"ManagedThing for identifier '{thing_id}' not found", second_delete_code_msg

    # Positive control: an unrelated, freshly created managed thing deletes cleanly with no error.
    control_id = _create_thing(ctx, iot)
    iot.delete_managed_thing(Identifier=control_id)
    control_get_code, control_get_code_msg = _error(lambda: iot.get_managed_thing(Identifier=control_id))
    assert control_get_code == "ResourceNotFoundException", control_get_code
    assert control_get_code_msg == 'Managed Thing resource not found.', control_get_code_msg


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it. ctx.client's `region`
    # override pins the region while keeping the runner's own credential wiring (the
    # leased real-AWS creds, or the emulator's shared endpoint) — no ambient-credential
    # fork needed.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_thing(ctx, iot) -> str:
    resp = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}",
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
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
