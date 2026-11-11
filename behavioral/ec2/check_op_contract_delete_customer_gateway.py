"""op-contract-delete-customer-gateway."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-customer-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCustomerGateway: a freshly created, unattached customer gateway deletes cleanly and
    transitions to the 'deleted' state; deleting an unknown customer gateway ID is rejected with
    the documented NotFound error.
    """
    ec2 = ctx.client("ec2")
    cgw = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.10",
        Type="ipsec.1",
        TagSpecifications=[
            {"ResourceType": "customer-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cgw-")}]}
        ],
    )["CustomerGateway"]
    cgw_id = cgw["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)))

    resp = ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected DeleteCustomerGateway to return 200, got {status}"

    def probe():
        gws = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])["CustomerGateways"]
        return gws[0]["State"] if gws else "deleted"

    state = _poll_until(probe, lambda s: s == "deleted", timeout_s=60, interval_s=3)
    assert state == "deleted", f"expected the gateway to reach deleted, got {state!r}"

    # Error boundary: referencing a customer gateway ID that never existed is rejected.
    fake_id = _zeroed_id(cgw_id)
    code, message = _error_of(lambda: ec2.delete_customer_gateway(CustomerGatewayId=fake_id))
    assert code == "InvalidCustomerGatewayID.NotFound", f"unexpected error code {code!r}"
    assert message == f"The customerGateway ID '{fake_id}' does not exist", message


def _error_of(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCustomerGatewayID.NotFound":
            raise


def _zeroed_id(real_id: str) -> str:
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'0' * len(suffix)}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
