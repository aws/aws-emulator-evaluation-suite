"""describe-addresses-attribute-max-results-below-the-allocation-count-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-addresses-attribute-max-results-below-the-allocation-count-rejected"
GROUP = "addresses"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddressesAttribute with explicit AllocationIds rejects a MaxResults below the
    number of ids given, and accepts one equal to it, returning every id in one page."""
    ec2 = ctx.client("ec2")

    alloc_a = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tag_spec(ctx.unique_name("sim2real-daap-a-")),
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_a))

    alloc_b = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=_tag_spec(ctx.unique_name("sim2real-daap-b-")),
    )["AllocationId"]
    ctx.on_cleanup(lambda: ec2.release_address(AllocationId=alloc_b))

    domain_a = f"{ctx.unique_name('sim2real-daap-ptr-a')}.example.com".lower()
    ec2.modify_address_attribute(AllocationId=alloc_a, DomainName=domain_a)
    expected_ptr_a = f"{domain_a}."

    # --- break: MaxResults below the number of requested AllocationIds is rejected, counting
    # the ids given rather than how many carry a domain-name customization ---
    code, message = _client_error(
        lambda: ec2.describe_addresses_attribute(
            AllocationIds=[alloc_a, alloc_b], Attribute="domain-name", MaxResults=1
        )
    )
    assert code == "InvalidMaxResults", f"expected InvalidMaxResults, got {code!r}"
    expected_message = (
        "The specified maximum results (1) must be greater than or equal to the number of "
        "Ipv4Ptrs specified (2)."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- legal neighbour: MaxResults equal to the id count succeeds in a single page ---
    both = ec2.describe_addresses_attribute(
        AllocationIds=[alloc_a, alloc_b], Attribute="domain-name", MaxResults=2
    )
    assert not both.get("NextToken"), (
        f"expected a single page for a matching MaxResults, got NextToken {both.get('NextToken')!r}"
    )
    seen = {entry["AllocationId"]: _ptr_value(entry) for entry in both["Addresses"]}
    assert seen.get(alloc_a) == expected_ptr_a, (
        f"expected {alloc_a} to carry PTR {expected_ptr_a!r}, got {seen.get(alloc_a)!r}"
    )

    # --- positive control: a single AllocationId with its own matching MaxResults still works ---
    single = ec2.describe_addresses_attribute(
        AllocationIds=[alloc_a], Attribute="domain-name", MaxResults=1
    )["Addresses"]
    assert len(single) == 1, f"expected exactly one entry for one AllocationId, got {single!r}"
    assert single[0]["AllocationId"] == alloc_a, (
        f"expected AllocationId {alloc_a!r}, got {single[0]['AllocationId']!r}"
    )
    assert _ptr_value(single[0]) == expected_ptr_a, (
        f"expected PTR {expected_ptr_a!r}, got {_ptr_value(single[0])!r}"
    )


def _ptr_value(entry):
    # AWS propagates the new PTR record asynchronously: right after ModifyAddressAttribute the
    # pending target lives in PtrRecordUpdate.Value, falling back to PtrRecord once converged.
    update = entry.get("PtrRecordUpdate") or {}
    return update.get("Value") or entry.get("PtrRecord")


def _tag_spec(name: str):
    return [{"ResourceType": "elastic-ip", "Tags": [{"Key": "Name", "Value": name}]}]


def _client_error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises, so a
    target accepting input real AWS refuses is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
