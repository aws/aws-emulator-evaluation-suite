"""provisioning-profile-lifecycle-status."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-profile-lifecycle-status"
GROUP = "state-machine"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateProvisioningProfile synchronously returns Status CREATED with claim-certificate
    material; an invalid CaCertificate is rejected without creating a second profile; delete
    removes it."""
    iot = _iot_client(ctx)
    name = ctx.unique_name("sim2real-provprof-")

    # The account-level custom endpoint is a singleton prerequisite for provisioning-profile
    # operations; create-or-adopt so this runs on a fresh account and on one already registered.
    try:
        iot.register_custom_endpoint()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise

    created = iot.create_provisioning_profile(
        ProvisioningType="FLEET_PROVISIONING", Name=name, Tags={"sim2real": CHECK}
    )
    profile_id = created["Id"]
    assert created["Status"] == "CREATED", f"expected Status CREATED, got {created['Status']}"
    assert created["ClaimCertificate"], "expected a non-empty ClaimCertificate, got none"
    ctx.on_cleanup(lambda: _delete_profile_ignore_missing(iot, profile_id))

    got = iot.get_provisioning_profile(Identifier=profile_id)
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    assert got["ProvisioningType"] == "FLEET_PROVISIONING", (
        f"expected ProvisioningType FLEET_PROVISIONING, got {got['ProvisioningType']!r}"
    )
    assert got["Status"] == "CREATED", f"expected Status CREATED, got {got['Status']!r}"

    bad_name = ctx.unique_name("sim2real-provprof-bad-")
    bad_code, bad_code_msg = _error(
        lambda: iot.create_provisioning_profile(
            ProvisioningType="FLEET_PROVISIONING",
            Name=bad_name,
            CaCertificate="not-a-pem-certificate",
            Tags={"sim2real": CHECK},
        )
    )
    assert bad_code == "ValidationException", f"expected ValidationException, got {bad_code!r}"
    assert bad_code_msg == "1 validation error detected: Value at 'caCertificate' failed to satisfy constraint: Member must satisfy regular expression pattern: -----BEGIN CERTIFICATE-----[\\s\\S]*-----END CERTIFICATE-----\\n?", bad_code_msg

    listed = {
        p["Name"]: p["Id"]
        for page in iot.get_paginator("list_provisioning_profiles").paginate()
        for p in page.get("Items", [])
    }
    assert listed.get(name) == profile_id, f"expected {name!r} listed as {profile_id!r}, got {listed.get(name)!r}"
    assert bad_name not in listed, f"invalid CaCertificate must not create a profile, found {bad_name!r}"

    iot.delete_provisioning_profile(Identifier=profile_id)
    not_found_code, not_found_code_msg = _error(lambda: iot.get_provisioning_profile(Identifier=profile_id))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on GetProvisioningProfile after delete, got {not_found_code!r}"
    )
    assert not_found_code_msg == 'Provisioning Profile resource not found', not_found_code_msg

    redelete_code, redelete_code_msg = _error(lambda: iot.delete_provisioning_profile(Identifier=profile_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting an already-deleted profile, got {redelete_code!r}"
    )
    assert redelete_code_msg == 'Provisioning Profile resource not found', redelete_code_msg


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1; the
    # runner's default region (us-west-2) has no endpoint for it. ctx.client's
    # `region=` override repins the region while keeping ctx's leased real-AWS
    # credentials and endpoint wiring -- unlike hand-rolling boto3.client(), which
    # drops them and resolves the ambient chain instead.
    return ctx.client("iot-managed-integrations", region="eu-west-1")
def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_profile_ignore_missing(iot, profile_id: str) -> None:
    try:
        iot.delete_provisioning_profile(Identifier=profile_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
