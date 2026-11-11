"""op-contract-deleteVpcEncryptionControl."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcEncryptionControl"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcEncryptionControl removes the control; a bogus control id is rejected."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.214.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vec-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    created = ec2.create_vpc_encryption_control(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "vpc-encryption-control", "vec")]
    )
    control_id = created["VpcEncryptionControl"]["VpcEncryptionControlId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id))

    ctx.on_cleanup(_cleanup)

    # success path: the control exists, is tied to the VPC, and reaches a terminal "create" state
    def _describe_control():
        try:
            return _items(
                ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id]),
                "VpcEncryptionControls",
                "VpcEncryptionControlSet",
            )[0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcEncryptionControlId.NotFound":
                # eventual consistency: the control may not be describable immediately after creation
                return {"State": "creating"}
            raise
        except IndexError:
            return {"State": "creating"}

    control = _poll_until(
        _describe_control,
        lambda c: c["State"] != "creating",
        timeout_s=90.0,
    )
    assert control["VpcId"] == vpc_id, f"expected VpcId {vpc_id!r}, got {control.get('VpcId')!r}"

    ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id)
    state["deleted"] = True

    def _probe_deleted():
        try:
            described = _items(
                ec2.describe_vpc_encryption_controls(VpcEncryptionControlIds=[control_id]),
                "VpcEncryptionControls",
                "VpcEncryptionControlSet",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcEncryptionControlId.NotFound":
                return "gone"
            raise
        return described[0]["State"] if described else "gone"

    _poll_until(_probe_deleted, lambda s: s in ("deleted", "gone"), timeout_s=90.0)

    # the dead id itself is unusable: a second delete of the exact control this check just removed
    # is rejected
    code, message = _error(lambda: ec2.delete_vpc_encryption_control(VpcEncryptionControlId=control_id))
    assert code == "InvalidVpcEncryptionControlId.NotFound", f"unexpected error re-deleting the already-deleted control: {code}: {message}"
    assert message == f"The vpc-encryption-control ID '{control_id}' does not exist", message

    # distinct error boundary: a syntactically valid but nonexistent control id is rejected
    bogus_id = _mutate_id(control_id)
    code, message = _error(lambda: ec2.delete_vpc_encryption_control(VpcEncryptionControlId=bogus_id))
    assert code == "InvalidVpcEncryptionControlId.NotFound", f"unexpected error deleting a nonexistent encryption control: {code}: {message}"
    assert message == f"The vpc-encryption-control ID '{bogus_id}' does not exist", message


def _items(resp: dict, *keys: str) -> list:
    for key in keys:
        if key in resp:
            return resp[key]
    return []


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidVpcEncryptionControlId.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
