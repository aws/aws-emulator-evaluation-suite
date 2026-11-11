"""op-contract-delete-tags."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-delete-tags"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTags removes only the targeted key, removes a key+value tag only when the value
    matches, and rejects a malformed resource id with InvalidID."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.99.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    ec2.create_tags(
        Resources=[vpc_id],
        Tags=[
            {"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tags-")},
            {"Key": "Environment", "Value": "sim2real-test"},
            {"Key": "Owner", "Value": "behavioral-suite"},
        ],
    )

    tags_before = _tags_of(ec2, vpc_id)
    assert tags_before.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test before delete, got {tags_before.get('Environment')!r}"
    )
    assert tags_before.get("Owner") == "behavioral-suite", (
        f"expected Owner=behavioral-suite before delete, got {tags_before.get('Owner')!r}"
    )

    resp = ec2.delete_tags(Resources=[vpc_id], Tags=[{"Key": "Environment"}])
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected DeleteTags to return HTTP 200, got {status}"

    tags_after = _tags_of(ec2, vpc_id)
    assert "Environment" not in tags_after, "targeted tag key should be gone"
    assert tags_after.get("Owner") == "behavioral-suite", "untargeted tag key must survive"
    assert tags_after.get("Name") == tags_before.get("Name"), "Name tag must survive"

    ec2.delete_tags(Resources=[vpc_id], Tags=[{"Key": "Owner", "Value": "does-not-match"}])
    still_there = _tags_of(ec2, vpc_id)
    assert still_there.get("Owner") == "behavioral-suite", (
        "delete with a mismatched value must not remove the tag"
    )

    ec2.delete_tags(Resources=[vpc_id], Tags=[{"Key": "Owner", "Value": "behavioral-suite"}])
    gone = _tags_of(ec2, vpc_id)
    assert "Owner" not in gone, "delete with a matching value must remove the tag"

    code, msg = _client_error(
        lambda: ec2.delete_tags(
            Resources=["not-a-real-resource-id"], Tags=[{"Key": "Name"}]
        )
    )
    assert code == "InvalidID", f"expected InvalidID, got {code!r}"
    expected_msg = "The ID 'not-a-real-resource-id' is not valid"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _tags_of(ec2: Any, resource_id: str) -> dict:
    desc = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])
    return {t["Key"]: t["Value"] for t in desc["Tags"]}


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
