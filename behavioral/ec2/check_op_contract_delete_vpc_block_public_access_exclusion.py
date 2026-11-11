"""op-contract-deleteVpcBlockPublicAccessExclusion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcBlockPublicAccessExclusion"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcBlockPublicAccessExclusion removes an exclusion; a bogus exclusion id is rejected."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.213.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "bpa-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    created = ec2.create_vpc_block_public_access_exclusion(
        VpcId=vpc_id,
        InternetGatewayExclusionMode="allow-bidirectional",
        TagSpecifications=[_tag_spec(ctx, "vpc-block-public-access-exclusion", "bpa")],
    )
    exclusion_id = created["VpcBlockPublicAccessExclusion"]["ExclusionId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpc_block_public_access_exclusion(ExclusionId=exclusion_id))

    ctx.on_cleanup(_cleanup)

    # success path: the exclusion exists and reaches a terminal "create" state.
    # immediately after CreateVpcBlockPublicAccessExclusion returns, real AWS can
    # briefly still respond to Describe with a NotFound for that exclusion id
    # (eventual consistency), so the probe must tolerate that instead of letting
    # the ClientError escape and abort the poll.
    def _describe_exclusion():
        try:
            items = _items(
                ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[exclusion_id]),
                "VpcBlockPublicAccessExclusions",
                "VpcBlockPublicAccessExclusionSet",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpcBlockPublicAccessExclusionId.NotFound":
                return None
            raise
        return items[0] if items else None

    exclusion = _poll_until(
        _describe_exclusion,
        lambda e: e is not None and e["State"] in ("create-complete", "create-failed"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    # "create-in-progress" is not the only non-terminal-success value the enum admits:
    # a poll that only excludes "create-in-progress" also treats "create-failed" as
    # terminal-success, letting a failed creation slip through with its request fields
    # echoed back. Assert the specific success state explicitly.
    assert exclusion["State"] == "create-complete", (
        f"expected exclusion to reach create-complete, got state={exclusion['State']!r}"
    )
    # the exclusion response identifies the excluded VPC via its ARN, not a bare VpcId field
    assert vpc_id in exclusion.get("ResourceArn", ""), (
        f"expected exclusion ResourceArn to reference {vpc_id}, got {exclusion!r}"
    )
    assert exclusion["InternetGatewayExclusionMode"] == "allow-bidirectional", (
        f"expected InternetGatewayExclusionMode allow-bidirectional, got {exclusion['InternetGatewayExclusionMode']!r}"
    )

    ec2.delete_vpc_block_public_access_exclusion(ExclusionId=exclusion_id)
    state["deleted"] = True

    def _probe_deleted():
        try:
            described = _items(
                ec2.describe_vpc_block_public_access_exclusions(ExclusionIds=[exclusion_id]),
                "VpcBlockPublicAccessExclusions",
                "VpcBlockPublicAccessExclusionSet",
            )
        except ClientError as exc:
            # once fully deleted, real AWS stops recognizing the id at all rather than
            # continuing to return it in a terminal "delete-complete" state
            if exc.response["Error"]["Code"] == "InvalidVpcBlockPublicAccessExclusionId.NotFound":
                return "gone"
            raise
        return described[0]["State"] if described else "gone"

    _poll_until(_probe_deleted, lambda s: s in ("delete-complete", "gone"), timeout_s=300.0, interval_s=5.0)

    # distinct error boundary: a syntactically valid but nonexistent exclusion id is rejected
    bogus_id = _mutate_id(exclusion_id)
    code, message = _error(lambda: ec2.delete_vpc_block_public_access_exclusion(ExclusionId=bogus_id))
    assert code == "InvalidVpcBlockPublicAccessExclusionId.NotFound", f"unexpected error deleting a nonexistent exclusion: {code}: {message}"
    assert message == f"The vpc-block-public-access-exclusion ID '{bogus_id}' does not exist", message


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
            "InvalidVpcBlockPublicAccessExclusionId.NotFound",
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
