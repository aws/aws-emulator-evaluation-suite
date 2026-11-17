"""create-tags-value-256-unicode-boundary-and-aws-prefixed-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tags-value-256-unicode-boundary-and-aws-prefixed-key-rejected"
GROUP = "tagging-boundaries"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags accepts a 256-Unicode-character tag value verbatim, rejects one Unicode
    character past that boundary, and rejects a tag key that begins with the reserved 'aws:'
    prefix while a sibling key without it still succeeds."""
    ec2 = ctx.client("ec2")
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(_delete_igw(ec2, igw_id))

    # 256 Unicode characters (mixing multi-byte code points) is the documented ceiling for a
    # tag value and must be stored verbatim, byte-for-byte.
    key_at = ctx.unique_name("sim2real-behav-tv256-")
    value_at = ("sim2réal-€-" * 30)[:255] + "✓"
    assert len(value_at) == 256, f"test value must be exactly 256 characters, got {len(value_at)}"
    ec2.create_tags(Resources=[igw_id], Tags=[{"Key": key_at, "Value": value_at}])
    stored = _tag_value(ec2, igw_id, key_at)
    assert stored == value_at, f"expected the 256-character value stored verbatim, got {stored!r}"

    # One character past the boundary is rejected, and the rejected call creates nothing.
    key_over = ctx.unique_name("sim2real-behav-tv257-")
    value_over = value_at + "x"
    code, message = _client_error(
        lambda: ec2.create_tags(Resources=[igw_id], Tags=[{"Key": key_over, "Value": value_over}])
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for a 257-character value, got {code!r}"
    expected = f"Value ( {value_over} ) for parameter value is invalid. Tag value exceeds the maximum length of 256 characters"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert _tag_value(ec2, igw_id, key_over) is None, (
        f"the rejected 257-character tag must not have been created, but key {key_over!r} is present"
    )

    # A tag key beginning with the reserved "aws:" prefix is rejected...
    reserved_key = "aws:" + ctx.unique_name("sim2real-behav-")
    code, message = _client_error(
        lambda: ec2.create_tags(Resources=[igw_id], Tags=[{"Key": reserved_key, "Value": "x"}])
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for an 'aws:'-prefixed key, got {code!r}"
    expected = f"Value ( {reserved_key} ) for parameter key is invalid. Tag keys starting with 'aws:' are reserved for internal use"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert _tag_value(ec2, igw_id, reserved_key) is None, (
        f"the rejected 'aws:'-prefixed tag must not have been created, but key {reserved_key!r} is present"
    )

    # ...while a sibling key one character shorter (no reserved prefix) still succeeds, proving
    # the refusal above is about the prefix and not a broken CreateTags call.
    plain_key = ctx.unique_name("sim2real-behav-aws-")
    ec2.create_tags(Resources=[igw_id], Tags=[{"Key": plain_key, "Value": "x"}])
    assert _tag_value(ec2, igw_id, plain_key) == "x", (
        f"a tag key without the reserved prefix must still be creatable on the same resource"
    )


def _tag_value(ec2, resource_id, key):
    tags_ = ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}, {"Name": "key", "Values": [key]}]
    )["Tags"]
    return tags_[0]["Value"] if tags_ else None


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_igw(ec2, igw_id: str):
    def run_delete() -> None:
        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
                raise

    return run_delete


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
