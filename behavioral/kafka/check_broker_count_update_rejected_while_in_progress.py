"""broker-count-update-rejected-while-in-progress."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "broker-count-update-rejected-while-in-progress"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."

# Client-fault codes the MSK control plane may return for a rejected mutation.
_CLIENT_FAULTS = {
    "NotFoundException",
    "BadRequestException",
    "ConflictException",
    "ForbiddenException",
    "UnauthorizedException",
    "TooManyRequestsException",
}


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx, name):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{name}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


def _bogus_operation_arn(cluster_arn):
    """A well-formed cluster-operation ARN under cluster_arn that was never issued."""
    base = cluster_arn.replace(":cluster/", ":cluster-operation/", 1)
    return f"{base}/00000000-0000-0000-0000-000000000000"


def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order (a raised exception is
    captured as its slot's value rather than propagating)."""
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
            results[idx] = exc
        resolved.add(idx)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_errors(results):
    """(code, message) for the _run_concurrent entries that raised (ClientError ->
    (Error.Code, Error.Message), other exceptions -> (class name, str)); successes are skipped."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            error = r.response.get("Error", {})
            errors.append((error.get("Code"), error.get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateBrokerCount against an unresolvable cluster fails with the same NotFoundException and message
    on three concurrent attempts and on an out-of-range target; DescribeClusterOperation shows no operation
    and ListClustersV2 no cluster."""
    msk = ctx.client("kafka")
    ghost_name = ctx.unique_name('sim2real-behav-nonexistent-')
    ghost = _bogus_cluster_arn(ctx, ghost_name)

    # Precondition: the cluster genuinely does not exist.
    precondition_code, precondition_message = _err(lambda: msk.describe_cluster(ClusterArn=ghost))
    assert (precondition_code, precondition_message) == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"precondition DescribeCluster: expected NotFoundException, got "
        f"{(precondition_code, precondition_message)}"
    )

    def attempt():
        return msk.update_broker_count(
            ClusterArn=ghost, CurrentVersion="K3AEGXETSR30VB", TargetNumberOfBrokerNodes=4
        )

    results = _run_concurrent([attempt for _ in range(3)])
    accepted = [r for r in results if not isinstance(r, BaseException)]
    assert not accepted, f"UpdateBrokerCount must not be accepted for a ghost cluster: {accepted}"

    errors = _concurrent_errors(results)
    assert len(errors) == 3, f"expected 3 rejections, got {errors}"
    assert len(set(errors)) == 1, f"concurrent rejections were not deterministic: {set(errors)}"
    assert {code for code, _ in errors} <= _CLIENT_FAULTS, f"rejection code not a client fault: {errors}"
    assert errors[0] == ("NotFoundException", _NOT_FOUND_MESSAGE), errors

    # No phantom operation may have been created by the rejected attempts.
    op_code = _err(
        lambda: msk.describe_cluster_operation(ClusterOperationArn=_bogus_operation_arn(ghost))
    )
    assert op_code == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"DescribeClusterOperation for a refused update must be NotFoundException, got {op_code}"
    )

    # The rejected cluster must also be absent from the account's own inventory -- an
    # independent read distinct from either Describe* call above.
    listed = msk.list_clusters_v2(ClusterNameFilter=ghost_name)["ClusterInfoList"]
    assert not listed, f"ghost cluster must not appear in ListClustersV2, got {listed}"

    # An out-of-range target must also be refused, not clamped.
    over = _err(
        lambda: msk.update_broker_count(
            ClusterArn=ghost, CurrentVersion="K3AEGXETSR30VB", TargetNumberOfBrokerNodes=100
        )
    )
    assert over == ("NotFoundException", _NOT_FOUND_MESSAGE), f"over-range target must be a client fault, got {over}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
