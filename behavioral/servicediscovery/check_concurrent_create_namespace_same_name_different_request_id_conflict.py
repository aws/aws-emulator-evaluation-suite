"""concurrent-create-namespace-same-name-different-request-id-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-namespace-same-name-different-request-id-conflict"
GROUP = "concurrency"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreatePrivateDnsNamespace calls for one Name and VPC with distinct
    CreatorRequestIds leave at least one SUCCESS, ListNamespaces lists exactly the namespaces whose
    operations succeeded, and a loser fails with NamespaceAlreadyExists or a FAIL with an ErrorMessage."""
    sd = ctx.client("servicediscovery")
    ec2 = ctx.client("ec2")

    vpc_id = _get_vpc_id(ec2, ctx=ctx)
    if vpc_id is None:
        raise AssertionError(
            "no VPC available in this account/region to race CreatePrivateDnsNamespace "
            "against; would be closed by provisioning a VPC ahead of the check"
        )

    name = ctx.unique_name("sim2real-conc-ns-") + ".example.com"

    def attempt(idx):
        from botocore.exceptions import ClientError

        try:
            resp = sd.create_private_dns_namespace(
                Name=name,
                Vpc=vpc_id,
                CreatorRequestId=f"{name}-req-{idx}",
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            return ("ok", resp["OperationId"])
        except ClientError as exc:
            return ("error", exc.response.get("Error", {}).get("Code"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(attempt, i) for i in range(2)]]

    winners = [o for o in outcomes if o[0] == "ok"]
    losers = [o for o in outcomes if o[0] == "error"]
    assert len(winners) >= 1, f"expected at least one racer to be accepted, got {outcomes}"

    terminal_ops = [_wait_operation(sd, opid) for _, opid in winners]
    successes = [op for op in terminal_ops if op["Status"] == "SUCCESS"]
    op_failures = [op for op in terminal_ops if op["Status"] == "FAIL"]
    assert successes, f"expected at least one accepted racer to reach SUCCESS, got {terminal_ops}"

    ns_ids = []
    for op in successes:
        ns_id = op["Targets"]["NAMESPACE"]
        ns_ids.append(ns_id)
        ctx.on_cleanup(lambda nid=ns_id: sd.delete_namespace(Id=nid))

    for op in successes:
        namespace = sd.get_namespace(Id=op["Targets"]["NAMESPACE"])["Namespace"]
        assert namespace["Name"] == name, f"expected namespace name {name!r}, got {namespace['Name']!r}"
        assert namespace["Type"] == "DNS_PRIVATE", f"expected DNS_PRIVATE, got {namespace['Type']!r}"

    if losers:
        # A synchronously-rejected racer must carry the specific conflict code, not a
        # generic error.
        assert losers[0][1] == "NamespaceAlreadyExists", f"loser got unexpected code {losers[0][1]!r}"
    elif op_failures:
        # Both were accepted synchronously but the loser's async provisioning failed --
        # it must fail with a concrete, non-empty reason, not silently vanish.
        assert op_failures[0].get("ErrorMessage"), f"expected non-empty ErrorMessage on losing op: {op_failures[0]}"

    listed = sd.list_namespaces(
        Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}]
    )["Namespaces"]
    listed_ids = {n["Id"] for n in listed}
    assert listed_ids == set(ns_ids), f"listed namespaces {listed_ids} != successful creates {set(ns_ids)}"


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
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s: {op}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
