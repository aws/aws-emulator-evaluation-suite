"""list-clusters-maxresults-above-hundred-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-clusters-maxresults-above-hundred-rejected"
GROUP = "boundary-validation"
SERVICES = ["ecs"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListClusters accepts the documented maxResults ceiling of 100 and lists a cluster this
    check created; maxResults 101 is refused."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-lcb-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(_teardown(lambda: ecs.delete_cluster(cluster=cluster_arn), "ClusterNotFoundException"))

    # ---- Boundary: the documented ceiling of 100 is accepted. ----
    seen: set[str] = set()
    token = None
    for _ in range(50):
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        page = ecs.list_clusters(**kwargs)
        seen.update(page["clusterArns"])
        token = page.get("nextToken")
        if not token:
            break
    assert cluster_arn in seen, (
        f"maxResults=100, the documented ceiling, must still list a cluster this check created; "
        f"it was absent from {len(seen)} cluster(s)"
    )

    # ---- Past the boundary: 101 is refused. ----
    code, message = _error(lambda: ecs.list_clusters(maxResults=101))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = "Max results can not be greater than 100"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
