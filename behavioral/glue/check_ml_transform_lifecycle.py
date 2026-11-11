"""ml-transform-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ml-transform-lifecycle"
GROUP = 'ml-transform'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx):
    """Create a dedicated, self-cleaning Glue-assumable IAM role and return its ARN."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_ml_transform_with_retry(glue, deadline_s=90.0, interval_s=5.0, **kwargs):
    """A just-created IAM role (and its just-attached policy) can take some seconds
    to propagate before Glue can successfully assume it; CreateMLTransform validates
    the role synchronously and returns AccessDeniedException or
    InvalidInputException("...assume role...") until propagation completes."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return glue.create_ml_transform(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            transient = code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume role" in message.lower()
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MLTransform create -> get (NOT_READY) -> update -> list -> delete."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    db_name = ctx.unique_name("sim2real-behav-db-")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    tbl_name = ctx.unique_name("sim2real-behav-tbl-")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": tbl_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "name", "Type": "string"},
                ],
                "Location": "s3://example-bucket/data/",
            },
        },
    )
    ctx.on_cleanup(lambda: glue.delete_table(DatabaseName=db_name, Name=tbl_name))

    transform_id = _create_ml_transform_with_retry(
        glue,
        Name=ctx.unique_name("sim2real-behav-mlt-"),
        InputRecordTables=[{"DatabaseName": db_name, "TableName": tbl_name}],
        Parameters={
            "TransformType": "FIND_MATCHES",
            "FindMatchesParameters": {"PrimaryKeyColumnName": "id"},
        },
        Role=role,
        Description="v1",
        Tags={"sim2real": CHECK},
    )["TransformId"]
    ctx.on_cleanup(lambda: _delete_ml_transform_if_exists(glue, transform_id))

    transform = glue.get_ml_transform(TransformId=transform_id)
    assert transform["Description"] == "v1", f"description not persisted: {transform}"
    # A brand-new transform has never been trained, so it cannot be used yet.
    assert transform["Status"] == "NOT_READY", (
        f"a newly created ML transform must start NOT_READY, got {transform['Status']}"
    )
    assert transform["InputRecordTables"][0]["TableName"] == tbl_name, (
        f"expected input table {tbl_name}, got {transform['InputRecordTables']}"
    )

    glue.update_ml_transform(TransformId=transform_id, Description="v2")
    assert glue.get_ml_transform(TransformId=transform_id)["Description"] == "v2", (
        "UpdateMLTransform did not persist Description"
    )

    assert transform_id in glue.list_ml_transforms()["TransformIds"], (
        "transform missing from ListMLTransforms"
    )
    assert transform_id in {
        t["TransformId"] for t in glue.get_ml_transforms()["Transforms"]
    }, "transform missing from GetMLTransforms"

    # No task runs have been requested for an untrained transform.
    runs = glue.get_ml_task_runs(TransformId=transform_id)["TaskRuns"]
    assert runs == [], f"an untrained transform must have no task runs, got {runs}"

    glue.delete_ml_transform(TransformId=transform_id)
    account = ctx.client("sts").get_caller_identity()["Account"]
    expected_message = f"Cannot find MLTransform in account {account} with handle {transform_id}"
    code, message = _error_code(lambda: glue.get_ml_transform(TransformId=transform_id))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after DeleteMLTransform, got {code}"
    )
    assert message == expected_message, (
        f"expected GetMLTransform message {expected_message!r} after DeleteMLTransform, got {message!r}"
    )


def _delete_ml_transform_if_exists(glue, transform_id):
    try:
        glue.delete_ml_transform(TransformId=transform_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
