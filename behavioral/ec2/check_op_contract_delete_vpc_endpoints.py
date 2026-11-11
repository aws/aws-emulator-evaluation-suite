"""op-contract-deleteVpcEndpoints."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpcEndpoints"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpcEndpoints deletes the valid endpoint and reports the bogus one in Unsuccessful, not raise."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.215.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpce-vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    created = ec2.create_vpc_endpoint(
        VpcId=vpc_id,
        ServiceName=f"com.amazonaws.{ctx.region}.s3",
        VpcEndpointType="Gateway",
        TagSpecifications=[_tag_spec(ctx, "vpc-endpoint", "vpce")],
    )
    endpoint_id = created["VpcEndpoint"]["VpcEndpointId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]))

    ctx.on_cleanup(_cleanup)

    endpoint = _poll_until(
        lambda: ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda e: e["State"].lower() == "available",
        timeout_s=120.0,
    )
    assert endpoint["VpcId"] == vpc_id, f"expected endpoint bound to {vpc_id}, got {endpoint['VpcId']!r}"

    # batch delete: one real endpoint id + one bogus one in the same request
    bogus_id = _mutate_id(endpoint_id)
    delete_resp = ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id, bogus_id])
    state["deleted"] = True

    unsuccessful = delete_resp["Unsuccessful"]
    assert len(unsuccessful) == 1, f"expected exactly one Unsuccessful entry, got {unsuccessful!r}"
    assert unsuccessful[0]["ResourceId"] == bogus_id, (
        f"expected the Unsuccessful entry to name the bogus id {bogus_id!r}, got {unsuccessful[0]['ResourceId']!r}"
    )
    assert unsuccessful[0]["Error"]["Code"] is not None and (
        unsuccessful[0]["Error"]["Code"].startswith("Invalid")
        and unsuccessful[0]["Error"]["Code"].endswith("NotFound")
    ), f"expected an Invalid*NotFound error for the bogus endpoint id, got {unsuccessful[0]['Error']}"

    # the real endpoint was still deleted despite the bogus one failing in the same batch
    def _probe_gone():
        try:
            described = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"]
        except ClientError as exc:
            # once fully deleted, real AWS stops recognizing the id at all rather than
            # continuing to return it in a terminal "deleted" state
            if exc.response["Error"]["Code"] == "InvalidVpcEndpointId.NotFound":
                return "gone"
            raise
        return described[0]["State"].lower() if described else "gone"

    _poll_until(_probe_gone, lambda s: s in ("deleted", "gone"), timeout_s=60.0)


# ===== helpers =====
def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _safe(fn):
    fn()


def _retry_delete(fn, timeout_s: float = 60.0):
    """Delete, retrying DependencyViolation every 2 s for up to timeout_s while the endpoint's route-table entries
    release; a resource already gone returns; any other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
