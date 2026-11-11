"""op-contract-delete-dhcp-options."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-dhcp-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# DescribeDhcpOptions spells its not-found code with the singular "DhcpOptionID", while
# DeleteDhcpOptions rejects a checksum-failing ID as Malformed with "DhcpOptionsId"; each is
# asserted exactly.
_DESCRIBE_NOT_FOUND = "InvalidDhcpOptionID.NotFound"
_DELETE_MALFORMED = "InvalidDhcpOptionsId.Malformed"
# The transient code DeleteDhcpOptions returns right after CreateDhcpOptions, before the new set
# has propagated; retried below and never asserted as the terminal outcome.
_DELETE_NOT_FOUND_TRANSIENT = "InvalidDhcpOptionsID.NotFound"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDhcpOptions deletes a new DHCP options set, which DescribeDhcpOptions then fails with
    InvalidDhcpOptionID.NotFound; a checksum-failing ID fails with InvalidDhcpOptionsId.Malformed
    (exact messages)."""
    ec2 = ctx.client("ec2")
    dhcp = ec2.create_dhcp_options(
        DhcpConfigurations=[{"Key": "domain-name", "Values": ["example.com"]}],
        TagSpecifications=[
            {"ResourceType": "dhcp-options", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-dopt-")}]}
        ],
    )["DhcpOptions"]
    dhcp_id = dhcp["DhcpOptionsId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dhcp_id)))

    # A freshly created set is not always immediately deletable: real AWS can answer
    # DeleteDhcpOptions with the transient NotFound code for a few seconds after Create. Retry
    # that specific code on a bounded deadline; any other error is a real failure.
    resp = _retry_transient_not_found(lambda: ec2.delete_dhcp_options(DhcpOptionsId=dhcp_id))
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    # DHCP options sets are hard-deleted: describing the deleted set is itself rejected.
    describe_code, describe_message = _error(lambda: ec2.describe_dhcp_options(DhcpOptionsIds=[dhcp_id]))
    assert describe_code == _DESCRIBE_NOT_FOUND, describe_code
    assert describe_message == f"The dhcpOption ID '{dhcp_id}' does not exist", describe_message

    # Error boundary: deleting a well-formed-but-invalid DHCP options ID is rejected as
    # Malformed (EC2 validates id shape/checksum before attempting a lookup).
    fake_id = _zeroed_id(dhcp_id)
    code, message = _error(lambda: ec2.delete_dhcp_options(DhcpOptionsId=fake_id))
    assert code == _DELETE_MALFORMED, code
    assert message == f"The dhcp-options ID '{fake_id}' is malformed", message


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _retry_transient_not_found(fn, deadline_s=20.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != _DELETE_NOT_FOUND_TRANSIENT or time.monotonic() >= deadline:
                raise
            time.sleep(1)


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidDhcpOptionsID.NotFound":
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
