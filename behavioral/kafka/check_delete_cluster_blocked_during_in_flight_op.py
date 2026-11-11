"""delete-cluster-blocked-during-in-flight-op."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-cluster-blocked-during-in-flight-op"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# MSK's refusal for a cluster or cluster operation that does not exist.
_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) for a ClientError. An unexpected SUCCESS
    raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
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
    """(code, message) for the _run_concurrent entries that raised (ClientError -> Error.Code and
    Error.Message, other exceptions -> class name and text); successes are skipped."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get("Error", {})
            errors.append((err.get("Code"), err.get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCluster for an unresolvable cluster fails with NotFoundException and its exact message alone,
    with a stale version and on three concurrent calls; DescribeClusterOperation and DescribeCluster then
    report not-found too."""
    msk = ctx.client("kafka")
    ghost = _bogus_cluster_arn(ctx)

    single_code, single_message = _err(lambda: msk.delete_cluster(ClusterArn=ghost))
    assert (single_code, single_message) == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"DeleteCluster: expected NotFoundException, got {(single_code, single_message)}"
    )

    stale = _err(lambda: msk.delete_cluster(ClusterArn=ghost, CurrentVersion="K3AEGXETSR30VB"))
    assert stale == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"stale-version DeleteCluster of a ghost cluster must be NotFoundException, got {stale}"
    )

    def attempt():
        return msk.delete_cluster(ClusterArn=ghost)

    results = _run_concurrent([attempt for _ in range(3)])
    accepted = [r for r in results if not isinstance(r, BaseException)]
    assert not accepted, f"DeleteCluster must not report success for a ghost cluster: {accepted}"
    errors = _concurrent_errors(results)
    assert len(errors) == 3, f"expected 3 rejections, got {errors}"
    assert set(errors) == {("NotFoundException", _NOT_FOUND_MESSAGE)}, (
        f"concurrent DeleteCluster rejections must all be NotFoundException, got {set(errors)}"
    )

    op_code = _err(
        lambda: msk.describe_cluster_operation(ClusterOperationArn=_bogus_operation_arn(ghost))
    )
    assert op_code == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"DescribeClusterOperation for refused deletes must be NotFoundException, got {op_code}"
    )

    post = _err(lambda: msk.describe_cluster(ClusterArn=ghost))
    assert post == ("NotFoundException", _NOT_FOUND_MESSAGE), (
        f"cluster must remain absent after refused deletes, got {post}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
