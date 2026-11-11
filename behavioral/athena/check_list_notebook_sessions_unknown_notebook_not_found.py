"""list-notebook-sessions-unknown-notebook-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-notebook-sessions-unknown-notebook-not-found"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListNotebookSessions on a well-formed unknown NotebookId raises InvalidRequestException naming
    the notebook, while a fresh real notebook returns an empty NotebookSessionsList: "no such
    notebook" and "no sessions" stay distinct."""
    athena = ctx.client("athena")

    # Negative: a syntactically valid (UUID-shaped) NotebookId that was never created.
    fake_notebook_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: athena.list_notebook_sessions(NotebookId=fake_notebook_id))
    assert code == "InvalidRequestException", (
        f"expected ListNotebookSessions on an unknown NotebookId to raise "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == f"Notebook {fake_notebook_id} was not found", (
        f"unexpected ListNotebookSessions message: {message!r}"
    )

    # Positive control: a real Spark-enabled workgroup + notebook.
    role_arn = _create_spark_execution_role(ctx)
    spark_engine_version = _pick_spark_engine_version(athena)

    wg_name = ctx.unique_name("sim2real-athena-sparkwg-")
    fake_bucket = ctx.unique_name("sim2real-athena-sparkout-")
    _create_work_group_with_retry(
        athena,
        wg_name,
        {
            "ExecutionRole": role_arn,
            "EngineVersion": {"SelectedEngineVersion": spark_engine_version},
            "ResultConfiguration": {"OutputLocation": f"s3://{fake_bucket}/"},
        },
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    notebook_id = athena.create_notebook(
        WorkGroup=wg_name, Name=ctx.unique_name("sim2real-athena-nb-")
    )["NotebookId"]

    resp = athena.list_notebook_sessions(NotebookId=notebook_id)
    assert resp["NotebookSessionsList"] == [], (
        f"expected a freshly created notebook with no sessions to report an empty "
        f"NotebookSessionsList, got {resp['NotebookSessionsList']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListNotebookSessions on an unknown NotebookId to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _create_spark_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-athena-spark-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "athena.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _pick_spark_engine_version(athena) -> str:
    versions = athena.list_engine_versions()["EngineVersions"]
    # Athena for Apache Spark offers two release lines: "PySpark engine version
    # N" (usable for in-console notebooks, which is what CreateNotebook/
    # ListNotebookSessions need) and "Apache Spark version N.N" (SageMaker
    # Unified Studio / Spark Connect only -- CreateNotebook rejects a
    # workgroup on that engine with "engine version is not supported for
    # notebook creation"). Prefer the PySpark line explicitly.
    for v in versions:
        if "pyspark" in v["SelectedEngineVersion"].lower():
            return v["SelectedEngineVersion"]
    for v in versions:
        if "spark" in v["SelectedEngineVersion"].lower():
            return v["SelectedEngineVersion"]
    raise AssertionError(f"no Spark engine version offered by ListEngineVersions: {versions}")


def _create_work_group_with_retry(
    athena, wg_name: str, configuration: dict, timeout_s: float = 60.0, interval_s: float = 5.0
) -> None:
    """Newly created IAM roles can take a few seconds to be assumable by Athena
    (cross-service IAM propagation); retry CreateWorkGroup until it accepts the
    ExecutionRole or the bounded window elapses."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            athena.create_work_group(
                Name=wg_name,
                Configuration=configuration,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateWorkGroup never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
