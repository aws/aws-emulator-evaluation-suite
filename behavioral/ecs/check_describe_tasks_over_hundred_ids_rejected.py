"""describe-tasks-over-hundred-ids-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-tasks-over-hundred-ids-rejected"
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
    """DescribeTasks accepts up to 100 task identifiers in one call, reporting each unknown
    one as a MISSING failure; a 101st identifier is refused before any lookup runs."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-ecs-dt-")
    cluster_arn = ecs.create_cluster(
        clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}]
    )["cluster"]["clusterArn"]
    ctx.on_cleanup(_teardown(lambda: ecs.delete_cluster(cluster=cluster_arn), "ClusterNotFoundException"))

    # ---- Boundary: exactly 100 identifiers (the documented maximum) is accepted. ----
    # A task id must have the 32- or 36-character shape of a UUID; a well-formed but
    # never-issued one exercises the per-id lookup rather than the id-shape validation.
    ids_100 = [str(uuid.uuid4()) for _ in range(100)]
    resp = ecs.describe_tasks(cluster=cluster_arn, tasks=ids_100)
    assert resp["tasks"] == [], f"made-up task ids resolved to real tasks: {resp['tasks']!r}"
    failures = resp["failures"]
    assert len(failures) == 100, f"expected 100 failures for 100 unknown ids, got {len(failures)}: {failures!r}"
    reasons = {f["reason"] for f in failures}
    assert reasons == {"MISSING"}, f"expected every failure reason to be MISSING, got {reasons!r}"
    expected_arns = sorted(f"arn:aws:ecs:{ctx.region}:{ctx.account}:task/{i}" for i in ids_100)
    failed_arns = sorted(f["arn"] for f in failures)
    assert failed_arns == expected_arns, f"failures named {failed_arns!r}, expected {expected_arns!r}"

    # ---- Past the boundary: 101 identifiers is refused, with no per-id failures returned. ----
    ids_101 = ids_100 + [str(uuid.uuid4())]
    code, message = _error(lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=ids_101))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected_message = "taskIds can have at most 100 items."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
