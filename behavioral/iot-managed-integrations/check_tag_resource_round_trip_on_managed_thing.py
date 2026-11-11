"""tag-resource-round-trip-on-managed-thing."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-on-managed-thing"
GROUP = "data-plane"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip tags on a managed thing."""
    iot = _iot_client(ctx)
    created = iot.create_managed_thing(
        Role="DEVICE",
        AuthenticationMaterial=_wifi_barcode(),
        AuthenticationMaterialType="WIFI_SETUP_QR_BAR_CODE",
    )
    thing_id = created["Id"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_thing_ignore_missing(iot, thing_id))

    iot.tag_resource(ResourceArn=arn, Tags={"env": "sim2real", "purpose": "test"})
    tags = iot.list_tags_for_resource(ResourceArn=arn)["tags"]
    assert tags == {"env": "sim2real", "purpose": "test"}, tags

    iot.untag_resource(ResourceArn=arn, TagKeys=["purpose"])
    remaining = iot.list_tags_for_resource(ResourceArn=arn)["tags"]
    assert remaining == {"env": "sim2real"}, remaining


def _wifi_barcode() -> str:
    # The only AuthenticationMaterial real AWS accepts on CreateManagedThing is the
    # WIFI_SETUP_QR_BAR_CODE envelope "UPC:<valid UPC-A>;SN:<12-digit serial>" -- an opaque random
    # string with AuthenticationMaterialType="DISCOVERED_DEVICE" is rejected with
    # ValidationException, so the tag round-trip under test never got a resource to run against.
    return f"UPC:012345678905;SN:{str(uuid.uuid4().int)[:12]}"


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it, so pin the region via
    # ctx.client's `region=` override, which keeps the run's credentials and endpoint
    # routing instead of resolving the ambient chain.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


def _delete_thing_ignore_missing(iot, thing_id: str) -> None:
    try:
        iot.delete_managed_thing(Identifier=thing_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
