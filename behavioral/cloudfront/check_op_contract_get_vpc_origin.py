"""op-contract-getVpcOrigin."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getVpcOrigin"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetVpcOrigin answers a malformed Id with InvalidArgument "Id format is invalid" and the Id of a deleted VPC
    origin (backed by an internal ALB) with EntityNotFound "The specified vpc origin does not exist"."""
    cf = ctx.client("cloudfront")
    if not hasattr(cf, "create_vpc_origin"):
        raise AssertionError("unreachable: create_vpc_origin not present in installed botocore")

    malformed_code, malformed_msg = _error(lambda: cf.get_vpc_origin(Id="not a valid id !!"))
    if malformed_code == "UnsupportedOperation":
        raise AssertionError("GetVpcOrigin answered UnsupportedOperation")
    assert malformed_code == "InvalidArgument", (
        f"expected InvalidArgument for a malformed Id, got {malformed_code}"
    )
    assert malformed_msg == "Id format is invalid", f"unexpected InvalidArgument message: {malformed_msg!r}"

    alb_arn = _create_minimal_alb(ctx)
    if alb_arn is None:
        raise AssertionError("the check's network has no subnets in 2 zones for the ALB")

    name = ctx.unique_name("sim2real-vpco-get-")
    try:
        created = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": alb_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
            }
        )
    except ClientError as exc:
        raise AssertionError(f"CreateVpcOrigin failed: {exc}")

    vo_id = created["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete(cf, vo_id))

    # A new VPC origin stays "Deploying" for a while, and DeleteVpcOrigin answers IllegalDelete until it is
    # deployed, so the delete is retried with a fresh ETag.
    _delete_with_retry(cf, vo_id, created["ETag"], deadline=time.monotonic() + 600.0, interval_s=10.0)

    # GetVpcOrigin can still succeed right after DeleteVpcOrigin returns 200, so not-found is polled for.
    missing_code, missing_msg = _poll_for_error(
        cf, vo_id, deadline=time.monotonic() + 420.0, interval_s=15.0
    )
    assert missing_code == "EntityNotFound", (
        f"expected EntityNotFound for a well-formed but deleted Id, got {missing_code}"
    )
    assert missing_msg == "The specified vpc origin does not exist", f"unexpected EntityNotFound message: {missing_msg!r}"
    assert missing_code != malformed_code


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_alb(ctx) -> "str | None":
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        return None

    name = ctx.unique_name("sim2real-vpco-get-alb-")[:32]
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb = resp["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_alb(ctx, lb_arn))
    return lb_arn


def _delete_alb(ctx, lb_arn: str) -> None:
    elbv2 = ctx.client("elbv2")
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


# DeleteVpcOrigin's answer while the VPC origin is still deploying.
_ILLEGAL_DELETE_MESSAGE = "The request failed because delete is not allowed for this vpc origin"


def _delete_with_retry(cf, vo_id: str, etag: str, deadline: float, interval_s: float) -> None:
    while True:
        try:
            cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            deploying = code == "IllegalDelete" and message == _ILLEGAL_DELETE_MESSAGE
            if not deploying or time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected DeleteVpcOrigin to eventually succeed once Deployed, got {code}: {message!r}"
                ) from exc
            time.sleep(min(interval_s, max(deadline - time.monotonic(), 0.0)))
            etag = cf.get_vpc_origin(Id=vo_id)["ETag"]


def _poll_for_error(cf, vo_id: str, deadline: float, interval_s: float) -> "tuple[str, str]":
    """Poll GetVpcOrigin until it raises; return that error's (code, message)."""
    while True:
        try:
            cf.get_vpc_origin(Id=vo_id)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                "GetVpcOrigin kept succeeding after DeleteVpcOrigin returned 200 -- "
                "the deleted id never became not-found"
            )
        time.sleep(min(interval_s, max(deadline - time.monotonic(), 0.0)))


def _safe_delete(cf, vo_id: str) -> None:
    try:
        current = cf.get_vpc_origin(Id=vo_id)
        cf.delete_vpc_origin(Id=vo_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
