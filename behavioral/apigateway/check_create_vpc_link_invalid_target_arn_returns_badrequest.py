"""create-vpc-link-invalid-target-arn-returns-badrequest."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-vpc-link-invalid-target-arn-returns-badrequest"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink targeting a well-formed but nonexistent NLB ARN is accepted, then the async
    provisioning settles on FAILED (never AVAILABLE), as seen by GetVpcLink and GetVpcLinks."""
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    fake_nlb_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        "loadbalancer/net/sim2real-nonexistent-nlb/0123456789abcdef"
    )
    name = ctx.unique_name("sim2real-vpclink-")

    created = apigw.create_vpc_link(
        name=name, targetArns=[fake_nlb_arn], tags={"sim2real": "create-vpc-link-invalid-target-arn"}
    )
    vpc_link_id = created["id"]
    assert created["status"] in ("PENDING", "FAILED"), (
        f"expected the synchronous create to accept the request as PENDING or resolve "
        f"immediately to FAILED, got {created['status']!r}"
    )

    def _cleanup_link():
        from botocore.exceptions import ClientError

        try:
            apigw.delete_vpc_link(vpcLinkId=vpc_link_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_link)

    final = _poll_until(
        lambda: apigw.get_vpc_link(vpcLinkId=vpc_link_id),
        lambda r: r["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=220.0,
        interval_s=10.0,
    )
    assert final["status"] == "FAILED", f"expected FAILED, got {final['status']}"

    # the effect did not happen: the link never reached a usable AVAILABLE state
    links = _list_vpc_links(apigw)
    matching = [v for v in links if v["id"] == vpc_link_id]
    assert matching and matching[0]["status"] == "FAILED", (
        f"expected the independent get_vpc_links listing to show {vpc_link_id} as FAILED, "
        f"got {matching[0]['status'] if matching else 'absent from listing'}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _list_vpc_links(apigw):
    items = []
    kwargs = {}
    while True:
        resp = apigw.get_vpc_links(**kwargs)
        items.extend(resp.get("items", []))
        position = resp.get("position")
        if not position:
            break
        kwargs["position"] = position
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
