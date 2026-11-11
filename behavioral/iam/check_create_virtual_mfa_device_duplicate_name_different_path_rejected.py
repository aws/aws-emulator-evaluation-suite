"""create-virtual-mfa-device-duplicate-name-different-path-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-virtual-mfa-device-duplicate-name-different-path-rejected"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVirtualMFADevice with an existing device's name and Path fails with
    EntityAlreadyExists and its exact message, while the same name under a different
    Path creates a second device with its own serial."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-mfaname-")
    path_a = "/sim2real-path-a/"

    dev1 = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=name, Path=path_a, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["VirtualMFADevice"]
    serial1 = dev1["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial1))

    # Same name AND same path -> conflicts with the existing entity's ARN.
    code, message = _error(
        lambda: iam.create_virtual_mfa_device(
            VirtualMFADeviceName=name, Path=path_a
        )
    )
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code!r}"
    expected = "MFA device already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: exactly one device carries this name+path combination
    devices = _listed(iam, "list_virtual_mfa_devices", "VirtualMFADevices")
    matching = [d for d in devices if d["SerialNumber"].endswith(f"/{name}")]
    assert len(matching) == 1, f"expected exactly one device named {name!r}, got {matching!r}"
    assert matching[0]["SerialNumber"] == serial1, (
        f"expected the surviving device to be the original {serial1!r}, got {matching[0]['SerialNumber']!r}"
    )

    # Same name, DIFFERENT path -> distinct ARN, so this is accepted (path-scoped
    # uniqueness, not account-wide).
    path_b = "/sim2real-path-b/"
    dev2 = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=name, Path=path_b, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["VirtualMFADevice"]
    serial2 = dev2["SerialNumber"]
    ctx.on_cleanup(lambda: iam.delete_virtual_mfa_device(SerialNumber=serial2))
    assert serial2 != serial1, "a different Path must yield a distinct SerialNumber/ARN"
    assert serial2.endswith(f"{path_b}{name}"), (
        f"expected the ARN to end with {path_b + name!r}, got {serial2!r}"
    )

    devices_after = _listed(iam, "list_virtual_mfa_devices", "VirtualMFADevices")
    matching_after = [d for d in devices_after if d["SerialNumber"].endswith(f"/{name}")]
    assert len(matching_after) == 2, f"expected two devices sharing name {name!r} under distinct paths, got {matching_after!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _listed(iam, operation, key):
    """Every item an IAM listing returns, across all pages."""
    return [item for page in iam.get_paginator(operation).paginate() for item in page[key]]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
