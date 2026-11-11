"""create-private-dns-namespace-invalid-domain-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-private-dns-namespace-invalid-domain-rejected"
GROUP = "overly-permissive"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePrivateDnsNamespace refuses an "arn:"-prefixed Name and a Name over 253 characters with
    InvalidInput and their exact messages and persists neither, while a valid name in the same VPC
    creates a DNS_PRIVATE namespace."""
    sd = ctx.client("servicediscovery")
    ec2 = ctx.client("ec2")

    vpc_id = _get_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError(
            "no VPC available in this account/region to isolate DNS-domain-syntax "
            "validation from VPC-id validation in CreatePrivateDnsNamespace; would be "
            "closed by provisioning a VPC ahead of the check"
        )

    arn_name = "arn:" + ctx.unique_name("sim2real-invalid-") + ".example.com"
    code, message = _error(lambda: sd.create_private_dns_namespace(Name=arn_name, Vpc=vpc_id))
    assert code == "InvalidInput", f"expected InvalidInput for 'arn:'-prefixed name, got {code!r}"
    assert message == (
        f"1 validation error detected: Value '{arn_name}' at 'name' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: ^(?!arn:)[!-~]{{1,253}}$"
    ), f"unexpected InvalidInput message: {message!r}"

    leaked = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [arn_name], "Condition": "EQ"}]
    )["Namespaces"]
    assert leaked == [], "the rejected namespace must not have been persisted"

    too_long_prefix = ctx.unique_name("sim2real-toolong-")
    too_long_name = too_long_prefix + ("x" * 260) + ".example.com"
    code2, message2 = _error(lambda: sd.create_private_dns_namespace(Name=too_long_name, Vpc=vpc_id))
    assert code2 == "InvalidInput", f"expected InvalidInput for over-length name, got {code2!r}"
    assert message2 == (
        f"2 validation errors detected: Value '{too_long_name}' at 'name' "
        f"failed to satisfy constraint: Member must satisfy regular expression pattern: ^(?!arn:)[!-~]{{1,253}}$; "
        f"Value '{too_long_name}' at 'name' failed to satisfy constraint: "
        f"Member must have length less than or equal to 253"
    ), f"unexpected InvalidInput message: {message2!r}"

    # too_long_name itself exceeds ListNamespaces' own 255-char filter-value limit, so the
    # effect-absent check filters on the (short, unique) prefix instead.
    leaked2 = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [too_long_prefix], "Condition": "BEGINS_WITH"}]
    )["Namespaces"]
    assert leaked2 == [], "the rejected over-length namespace must not have been persisted"

    good_name = ctx.unique_name("sim2real-goodns-") + ".example.com"
    resp = sd.create_private_dns_namespace(
        Name=good_name, Vpc=vpc_id, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    operation = _wait_operation(sd, resp["OperationId"])
    ns_id = operation["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: sd.delete_namespace(Id=ns_id))

    namespace = sd.get_namespace(Id=ns_id)["Namespace"]
    assert namespace["Name"] == good_name, f"expected Name={good_name!r}, got {namespace['Name']!r}"
    assert namespace["Type"] == "DNS_PRIVATE", f"expected Type='DNS_PRIVATE', got {namespace['Type']!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
