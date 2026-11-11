"""list-namespaces-filter-by-type-deterministic."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-namespaces-filter-by-type-deterministic"
GROUP = "ordering"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNamespaces filtered by TYPE returns only namespaces of that type, and each of the three
    namespaces the check creates (DNS_PRIVATE, DNS_PUBLIC, HTTP) appears under its own type's filter
    and no other."""
    sd = ctx.client("servicediscovery")
    ec2 = ctx.client("ec2")

    vpc_id = _get_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError(
            "no VPC available in this account/region to create the DNS_PRIVATE namespace "
            "needed for this filter comparison; would be closed by provisioning a VPC "
            "ahead of the check"
        )

    tags = [{"Key": "sim2real", "Value": CHECK}]
    http_id = _create_and_wait(
        ctx,
        sd,
        lambda: sd.create_http_namespace(
            Name=ctx.unique_name("sim2real-typ-http-"), Tags=tags
        ),
    )
    private_id = _create_and_wait(
        ctx,
        sd,
        lambda: sd.create_private_dns_namespace(
            Name=ctx.unique_name("sim2real-typ-priv-") + ".example.com",
            Vpc=vpc_id,
            Tags=tags,
        ),
    )
    public_id = _create_and_wait(
        ctx,
        sd,
        lambda: sd.create_public_dns_namespace(
            Name=ctx.unique_name("sim2real-typ-pub-") + ".com", Tags=tags
        ),
    )

    private_list = _list_by_type(sd, "DNS_PRIVATE")
    public_list = _list_by_type(sd, "DNS_PUBLIC")
    http_list = _list_by_type(sd, "HTTP")

    for summary in private_list:
        assert summary["Type"] == "DNS_PRIVATE", f"cross-type leakage in DNS_PRIVATE filter: {summary}"
    for summary in public_list:
        assert summary["Type"] == "DNS_PUBLIC", f"cross-type leakage in DNS_PUBLIC filter: {summary}"
    for summary in http_list:
        assert summary["Type"] == "HTTP", f"cross-type leakage in HTTP filter: {summary}"

    private_ids = {s["Id"] for s in private_list}
    public_ids = {s["Id"] for s in public_list}
    http_ids = {s["Id"] for s in http_list}

    assert private_id in private_ids and private_id not in public_ids and private_id not in http_ids, (
        f"expected {private_id} only under DNS_PRIVATE filter; "
        f"private={private_id in private_ids} public={private_id in public_ids} http={private_id in http_ids}"
    )
    assert public_id in public_ids and public_id not in private_ids and public_id not in http_ids, (
        f"expected {public_id} only under DNS_PUBLIC filter; "
        f"public={public_id in public_ids} private={public_id in private_ids} http={public_id in http_ids}"
    )
    assert http_id in http_ids and http_id not in private_ids and http_id not in public_ids, (
        f"expected {http_id} only under HTTP filter; "
        f"http={http_id in http_ids} private={http_id in private_ids} public={http_id in public_ids}"
    )


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


def _create_and_wait(ctx, sd, create_fn):
    resp = create_fn()
    operation = _wait_operation(sd, resp["OperationId"])
    ns_id = operation["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=ns_id))
    return ns_id


def _list_by_type(sd, type_value):
    out = []
    kwargs = {"Filters": [{"Name": "TYPE", "Values": [type_value], "Condition": "EQ"}]}
    while True:
        resp = sd.list_namespaces(**kwargs)
        out.extend(resp.get("Namespaces", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return out
        kwargs["NextToken"] = next_token


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
