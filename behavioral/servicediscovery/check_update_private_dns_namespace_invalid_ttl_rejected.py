"""update-private-dns-namespace-invalid-ttl-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-private-dns-namespace-invalid-ttl-rejected"
GROUP = "overly-permissive"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrivateDnsNamespace with an SOA TTL above 2147483647 is refused with InvalidInput and its
    exact message and leaves the persisted TTL unchanged, while an in-range TTL update persists."""
    sd = ctx.client("servicediscovery")
    ec2 = ctx.client("ec2")

    vpc_id = _get_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError(
            "no VPC available in this account/region to create a private DNS namespace "
            "for the UpdatePrivateDnsNamespace TTL check; would be closed by provisioning "
            "a VPC ahead of the check"
        )

    name = ctx.unique_name("sim2real-ttlns-") + ".example.com"
    create_resp = sd.create_private_dns_namespace(
        Name=name, Vpc=vpc_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    create_op = _wait_operation(sd, create_resp["OperationId"])
    ns_id = create_op["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=ns_id))

    original_ttl = sd.get_namespace(Id=ns_id)["Namespace"]["Properties"]["DnsProperties"]["SOA"]["TTL"]

    bad_ttl = 9_999_999_999  # far beyond the documented max of 2147483647
    error = _client_error(
        lambda: sd.update_private_dns_namespace(
            Id=ns_id,
            Namespace={"Properties": {"DnsProperties": {"SOA": {"TTL": bad_ttl}}}},
        )
    )
    assert error.get("Code") == "InvalidInput", f"expected InvalidInput for out-of-range TTL, got {error!r}"
    expected_message = (
        f"1 validation error detected: Value '{bad_ttl}' at 'namespace.properties.dnsProperties.sOA.tTL' "
        "failed to satisfy constraint: Member must have value less than or equal to 2147483647"
    )
    assert error.get("Message") == expected_message, f"unexpected InvalidInput message: {error.get('Message')!r}"

    unchanged_ttl = sd.get_namespace(Id=ns_id)["Namespace"]["Properties"]["DnsProperties"]["SOA"]["TTL"]
    assert unchanged_ttl == original_ttl, "rejected TTL update must not have persisted"

    good_ttl = 120 if original_ttl != 120 else 121
    update_resp = sd.update_private_dns_namespace(
        Id=ns_id,
        Namespace={"Properties": {"DnsProperties": {"SOA": {"TTL": good_ttl}}}},
    )
    _wait_operation(sd, update_resp["OperationId"])

    updated_ttl = _poll_until(
        lambda: sd.get_namespace(Id=ns_id)["Namespace"]["Properties"]["DnsProperties"]["SOA"]["TTL"],
        lambda v: v == good_ttl,
        timeout_s=60.0,
        interval_s=5.0,
    )
    assert updated_ttl == good_ttl, f"expected persisted TTL {good_ttl}, got {updated_ttl}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_vpc_id(ec2, *, ctx):
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}], MaxResults=5)
    vpcs = resp.get("Vpcs", [])
    return vpcs[0]["VpcId"] if vpcs else None


def _wait_operation(sd, operation_id, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    op = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            break
        time.sleep(interval_s)
    if op is None or op["Status"] != "SUCCESS":
        raise AssertionError(f"operation {operation_id} did not reach SUCCESS: {op}")
    return op


def _poll_until(probe, predicate, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
