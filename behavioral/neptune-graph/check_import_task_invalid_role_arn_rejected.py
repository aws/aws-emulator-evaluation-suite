"""import-task-invalid-role-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-task-invalid-role-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["neptune-graph"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartImportTask rejects a non-ARN roleArn and a foreign-account roleArn with AccessDeniedException
    and their exact messages, while a role trusting neptune-graph.amazonaws.com passes that gate and
    fails with ValidationException on the source format: roleArn is authorized first."""
    ng = ctx.client("neptune-graph")
    graph_id = "g-0000000000"
    source = "s3://sim2real-nonexistent-bucket/prefix/"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    # A syntactically-invalid (non-ARN) roleArn string.
    code, message = _error(
        lambda: ng.start_import_task(graphIdentifier=graph_id, source=source, roleArn="not-an-arn")
    )
    assert code == "AccessDeniedException", f"CODE={code!r}"
    assert message == f"User: {caller_arn} is not authorized to perform: null", message

    # A syntactically well-formed roleArn pointing at a foreign/nonexistent account+role gets the
    # identical error code -- confirming authorization, not ARN shape, is what's being enforced.
    code2, message2 = _error(
        lambda: ng.start_import_task(
            graphIdentifier=graph_id,
            source=source,
            roleArn="arn:aws:iam::111111111111:role/sim2real-import-role",
        )
    )
    assert code2 == "AccessDeniedException", f"CODE={code2!r}"
    assert message2 == "Cross-account pass role is not allowed.", message2

    # Positive control: a real, correctly-trusted role gets past the roleArn-authorization gate
    # entirely, so the failure becomes ValidationException instead. Without this,
    # code == code2 == AccessDeniedException is indistinguishable from StartImportTask
    # denying every call regardless of roleArn.
    role_arn = _create_authorized_import_role(ctx)
    code3, message3 = _poll_until(
        lambda: _error(
            lambda: ng.start_import_task(graphIdentifier=graph_id, source=source, roleArn=role_arn)
        ),
        lambda err: err[0] != "AccessDeniedException",
        timeout_s=60,
        interval_s=5,
        reason="freshly-created IAM role trust can take a few seconds to propagate to neptune-graph's own AssumeRole check",
    )
    assert code3 == "ValidationException", f"CODE={code3!r}"
    assert message3 == "Source format should be specified when Source type is S3.", message3


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises: a target that
    accepts a call AWS refuses is the clearest mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s, interval_s, reason):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{reason}: condition not met within {timeout_s}s; last={last!r}")


def _create_authorized_import_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ng-import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "neptune-graph.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
