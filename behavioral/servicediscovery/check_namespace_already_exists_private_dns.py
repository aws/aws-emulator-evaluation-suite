"""namespace-already-exists-private-dns."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-already-exists-private-dns"
GROUP = "error-semantics"
SERVICES = ["servicediscovery"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two CreatePrivateDnsNamespace calls racing for one Name and VPC with distinct CreatorRequestIds
    leave only successfully created namespaces listed under that name, a loser refused with
    NamespaceAlreadyExists or failing with an ErrorMessage; a completed CreatorRequestId is reusable."""
    sd = ctx.client("servicediscovery")
    vpc_id = _get_vpc_id(ctx)
    name = f"{ctx.unique_name('sim2real-exists-ns')}.example.com"
    crid_a = ctx.unique_name("sim2real-crid-a")
    crid_b = ctx.unique_name("sim2real-crid-b")

    def _do_create(crid):
        try:
            return (
                "ok",
                sd.create_private_dns_namespace(
                    Name=name, Vpc=vpc_id, CreatorRequestId=crid,
                    Tags=[{"Key": "sim2real-check", "Value": CHECK}],
                ),
            )
        except ClientError as e:
            return ("err", e)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_do_create, crid_a)
        fut_b = pool.submit(_do_create, crid_b)
        kind_a, res_a = fut_a.result()
        kind_b, res_b = fut_b.result()

    results = [(kind_a, res_a), (kind_b, res_b)]
    oks = [r for k, r in results if k == "ok"]
    errs = [r for k, r in results if k == "err"]

    assert len(oks) >= 1, f"expected at least one of the two racing creates to succeed: {results}"

    # Both requests may be *accepted* synchronously (each gets an OperationId) even though
    # only one will actually end up owning the name -- the conflict can be resolved
    # asynchronously via the Operation's terminal status rather than as an immediate
    # ClientError. Wait every accepted operation out to a terminal state and classify.
    terminal_ops = [_wait_operation(ctx, ok["OperationId"]) for ok in oks]
    successes = [op for op in terminal_ops if op["Status"] == "SUCCESS"]
    failures = [op for op in terminal_ops if op["Status"] == "FAIL"]

    assert len(successes) >= 1, f"expected at least one racing create to reach SUCCESS: {terminal_ops}"
    ns_id = successes[0]["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ns_id))
    for extra in successes[1:]:
        extra_ns_id = extra["Targets"]["NAMESPACE"]
        if extra_ns_id != ns_id:
            ctx.on_cleanup(lambda nid=extra_ns_id: _safe_delete_namespace(ctx, nid))

    if errs:
        # One request was rejected synchronously as an already-existing-name conflict.
        err = errs[0]
        code = err.response["Error"]["Code"]
        assert code == "NamespaceAlreadyExists", f"expected NamespaceAlreadyExists, got {code}"
        # message varies: AWS resolves this race through the losing Operation's FAIL status, so
        # no synchronous NamespaceAlreadyExists message is known to pin.
        reported_ns_id = err.response.get("NamespaceId") or err.response["Error"].get("NamespaceId")
        if reported_ns_id is not None:
            assert reported_ns_id == ns_id
    elif failures:
        # Both were accepted synchronously, but the loser's async provisioning failed --
        # it must fail with a real, non-empty reason (a conflict on the shared name),
        # not silently succeed as an independent second namespace.
        assert failures[0].get("ErrorMessage"), f"expected a non-empty ErrorMessage on the losing operation: {failures[0]}"
    else:
        # Both accepted and both succeeded -- acceptable only if Cloud Map/Route 53 truly
        # allow two independent namespaces sharing a name. That independence is the real
        # claim: the two SUCCESS operations must not have been server-side coalesced into
        # a single namespace reported twice.
        distinct_ns_ids = {op["Targets"]["NAMESPACE"] for op in successes}
        assert len(distinct_ns_ids) == 2, (
            f"expected two DISTINCT namespaces if both racers reached SUCCESS, "
            f"got {distinct_ns_ids} from {successes}"
        )

    # Effect check: at most the number of namespaces actually SUCCESS-created exist under
    # `name`, and every one of them is accounted for above.
    listed = sd.list_namespaces(Filters=[{"Name": "NAME", "Values": [name], "Condition": "EQ"}])["Namespaces"]
    listed_ids = {n["Id"] for n in listed}
    success_ids = {op["Targets"]["NAMESPACE"] for op in successes}
    assert listed_ids == success_ids, f"expected listed namespaces {listed_ids} to match successful creates {success_ids}"


    # Positive control: a CreatorRequestId whose own operation already completed is not
    # blocked by an unrelated, later, distinctly-named create.
    other_name = f"{ctx.unique_name('sim2real-exists-ns2')}.example.com"
    resp2 = sd.create_private_dns_namespace(
        Name=other_name, Vpc=vpc_id, CreatorRequestId=crid_a,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    op3 = _wait_operation(ctx, resp2["OperationId"])
    assert op3["Status"] == "SUCCESS", f"reused-crid create ended in {op3['Status']}: {op3.get('ErrorMessage')}"
    ns3_id = op3["Targets"]["NAMESPACE"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(ctx, ns3_id))
    got3 = sd.get_namespace(Id=ns3_id)["Namespace"]
    assert got3["Name"] == other_name


def _wait_operation(ctx, operation_id, timeout_s: float = 240.0, interval_s: float = 3.0):
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    while True:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        if time.monotonic() > deadline:
            raise AssertionError(
                f"operation {operation_id} did not reach a terminal state within {timeout_s}s "
                f"(last status={op['Status']})"
            )
        time.sleep(interval_s)


def _get_vpc_id(ctx) -> str:
    ec2 = ctx.client("ec2")
    resp = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])
    vpcs = resp.get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    return vpcs[0]["VpcId"]


def _safe_delete_namespace(ctx, namespace_id: str) -> None:
    sd = ctx.client("servicediscovery")
    try:
        resp = sd.delete_namespace(Id=namespace_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NamespaceNotFound":
            raise
        return
    op_id = resp.get("OperationId")
    if not op_id:
        return
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            op = sd.get_operation(OperationId=op_id)["Operation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "OperationNotFound":
                raise
            return
        if op["Status"] in ("SUCCESS", "FAIL"):
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
