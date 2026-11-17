"""create-tags-key-and-value-length-boundaries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-tags-key-and-value-length-boundaries-rejected"
GROUP = "tagging"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags accepts a 128-character key and a 256-character value, rejects one character
    past each boundary, and accepts a value holding characters outside the universal tag
    character set that EC2 itself does not restrict."""
    ec2 = ctx.client("ec2")
    vpc_id = ctx.network().vpc_id

    group_name = ctx.unique_name("sim2real-tagbound-")
    sg_id = ec2.create_security_group(
        GroupName=group_name,
        Description="sim2real tag key/value length boundary check",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": group_name}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=sg_id))

    # --- key boundary: 128 characters succeeds, 129 is rejected ---
    key_at_max = "k" * 128
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": key_at_max, "Value": "ok"}])
    assert _tag_value(ec2, sg_id, key_at_max) == "ok", (
        f"expected the 128-character key to round-trip, found none with value 'ok'"
    )

    key_over_max = "k" * 129
    code, message = _client_error(
        lambda: ec2.create_tags(Resources=[sg_id], Tags=[{"Key": key_over_max, "Value": "x"}])
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_key_message = (
        f"Value ( {key_over_max} ) for parameter key is invalid. "
        "Tag key exceeds the maximum length of 128 characters"
    )
    assert message == expected_key_message, (
        f"expected message {expected_key_message!r}, got {message!r}"
    )
    assert _tag_value(ec2, sg_id, key_over_max) is None, (
        "the oversized key must not have landed on the resource"
    )

    # --- positive control: an ordinary tag still succeeds after the key rejection ---
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "sim2real-after-key-reject", "Value": "still-works"}])
    assert _tag_value(ec2, sg_id, "sim2real-after-key-reject") == "still-works", (
        "CreateTags must not be wedged by the oversized-key rejection"
    )

    # --- value boundary: 256 characters succeeds, 257 is rejected ---
    value_at_max = "v" * 256
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "sim2real-value-max", "Value": value_at_max}])
    assert _tag_value(ec2, sg_id, "sim2real-value-max") == value_at_max, (
        "expected the 256-character value to round-trip exactly"
    )

    value_over_max = "v" * 257
    code2, message2 = _client_error(
        lambda: ec2.create_tags(
            Resources=[sg_id], Tags=[{"Key": "sim2real-value-over", "Value": value_over_max}]
        )
    )
    assert code2 == "InvalidParameterValue", f"expected InvalidParameterValue, got {code2!r}"
    expected_value_message = (
        f"Value ( {value_over_max} ) for parameter value is invalid. "
        "Tag value exceeds the maximum length of 256 characters"
    )
    assert message2 == expected_value_message, (
        f"expected message {expected_value_message!r}, got {message2!r}"
    )
    assert _tag_value(ec2, sg_id, "sim2real-value-over") is None, (
        "the oversized value's key must not have landed on the resource"
    )

    # --- positive control: an ordinary tag still succeeds after the value rejection ---
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "sim2real-after-value-reject", "Value": "still-works"}])
    assert _tag_value(ec2, sg_id, "sim2real-after-value-reject") == "still-works", (
        "CreateTags must not be wedged by the oversized-value rejection"
    )

    # --- EC2 itself does not restrict tag values to the cross-service character set ---
    unicode_value = "Café-北京-日本語-#!?"
    ec2.create_tags(Resources=[sg_id], Tags=[{"Key": "sim2real-unicode", "Value": unicode_value}])
    assert _tag_value(ec2, sg_id, "sim2real-unicode") == unicode_value, (
        f"expected the unicode/punctuation value to round-trip exactly, "
        f"got {_tag_value(ec2, sg_id, 'sim2real-unicode')!r}"
    )


def _tag_value(ec2, resource_id: str, key: str):
    found = ec2.describe_tags(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}, {"Name": "key", "Values": [key]}]
    )["Tags"]
    return found[0]["Value"] if found else None


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
