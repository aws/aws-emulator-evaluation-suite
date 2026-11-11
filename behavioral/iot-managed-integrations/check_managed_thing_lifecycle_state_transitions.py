"""managed-thing-lifecycle-state-transitions."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-thing-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateManagedThing starts UNASSOCIATED, UpdateManagedThing persists, DeleteManagedThing removes it."""
    iot = _iot_client(ctx)

    created = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        Name=ctx.unique_name("sim2real-mt-"),
    )
    thing_id = created["Id"]
    assert created["Arn"], f"CreateManagedThing returned no Arn: {created!r}"
    iot.tag_resource(ResourceArn=created["Arn"], Tags={"env": "sim2real"})
    ctx.on_cleanup(lambda: _delete_thing_ignore_missing(iot, thing_id))

    got = iot.get_managed_thing(Identifier=thing_id)
    assert got["ProvisioningStatus"] == "UNASSOCIATED", got["ProvisioningStatus"]
    assert got["Role"] == "DEVICE", got["Role"]

    # Break exactly one thing: the same WIFI_SETUP_QR_BAR_CODE envelope as the create that
    # just succeeded, but with characters outside the allowed pattern in the serial number.
    # The material type is held constant so the rejection is attributable to the material and
    # not to the type. The create above already proved a well-formed material succeeds.
    bad_code, bad_code_msg = _error(
        lambda: iot.create_managed_thing(
            Role="DEVICE",
            AuthenticationMaterial="UPC:012345678905;SN:not-allowed-éé\U0001f600",
            AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
        )
    )
    assert bad_code == "ValidationException", bad_code
    assert bad_code_msg == '1 validation error detected: Value at \'authenticationMaterial\' failed to satisfy constraint: Member must satisfy regular expression pattern: [0-9A-Za-z!#$%&()*\\+\\-;<=>?@^_`{|}~\\/: {},\\\\"]+', bad_code_msg

    new_name = ctx.unique_name("sim2real-mt-renamed-")
    iot.update_managed_thing(Identifier=thing_id, Name=new_name)
    updated = iot.get_managed_thing(Identifier=thing_id)
    assert updated["Name"] == new_name, updated["Name"]

    iot.delete_managed_thing(Identifier=thing_id)
    not_found_code, not_found_code_msg = _error(lambda: iot.get_managed_thing(Identifier=thing_id))
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_code_msg == 'Managed Thing resource not found.', not_found_code_msg

    # A mutation on the now-dead id must fail the same way an independent read does.
    dead_update_code, dead_update_code_msg = _error(
        lambda: iot.update_managed_thing(Identifier=thing_id, Name=ctx.unique_name("sim2real-mt-dead-"))
    )
    assert dead_update_code == "ResourceNotFoundException", dead_update_code
    assert dead_update_code_msg == f"ManagedThing for identifier '{thing_id}' not found", dead_update_code_msg


def _wifi_barcode() -> str:
    # A CUSTOM_PROTOCOL_QR_BAR_CODE JSON blob is rejected with ValidationException, so the lifecycle
    # under test never had a managed thing to walk.
    return f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so on real AWS we
    # pin the client to a supported region via ctx.client's region override (leased
    # creds, same endpoint wiring as every other client). On an emulator, keep using
    # ctx.client's single shared endpoint.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_thing_ignore_missing(iot, thing_id: str) -> None:
    try:
        iot.delete_managed_thing(Identifier=thing_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
