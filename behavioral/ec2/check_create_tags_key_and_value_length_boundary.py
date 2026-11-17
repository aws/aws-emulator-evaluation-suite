"""create-tags-key-and-value-length-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tags-key-and-value-length-boundary"
GROUP = "tagging"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTags rejects a tag key or value one character past its documented maximum
    length, and neither rejection leaves a tag on the resource or blocks a key/value at
    the maximum length from being accepted on the same resource.
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-taglen-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    max_key = "k" * 128
    over_key = "k" * 129
    max_value = "v" * 256
    over_value = "v" * 257

    # --- key one character past the documented maximum is rejected ---
    code, message = _error(lambda: ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": over_key, "Value": "x"}]))
    assert (code, message) == (
        "InvalidParameterValue",
        f"Value ( {over_key} ) for parameter key is invalid. Tag key exceeds the maximum length of 128 characters",
    ), f"unexpected rejection for a 129-char key: {code!r} ({message!r})"
    _assert_no_tag_with_key(ec2, vpc_id, over_key)

    # --- value one character past the documented maximum is rejected ---
    code, message = _error(lambda: ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-overlong-value", "Value": over_value}]))
    assert (code, message) == (
        "InvalidParameterValue",
        f"Value ( {over_value} ) for parameter value is invalid. Tag value exceeds the maximum length of 256 characters",
    ), f"unexpected rejection for a 257-char value: {code!r} ({message!r})"
    _assert_no_tag_with_key(ec2, vpc_id, "sim2real-overlong-value")

    # --- positive control: a key and value exactly at the maximum are accepted ---
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": max_key, "Value": max_value}])
    described = _tag_value(ec2, vpc_id, max_key)
    assert described == max_value, f"expected the 256-char value to round-trip, got {described!r}"


def _tag_value(ec2, resource_id: str, key: str) -> str | None:
    desc = ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}, {"Name": "key", "Values": [key]}]
    )
    found = desc.get("Tags", [])
    return found[0]["Value"] if found else None


def _assert_no_tag_with_key(ec2, resource_id: str, key: str) -> None:
    desc = ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}, {"Name": "key", "Values": [key]}]
    )
    found = desc.get("Tags", [])
    assert found == [], f"a rejected CreateTags call still left a tag under key {key!r}: {found!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
