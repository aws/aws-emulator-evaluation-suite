"""recipe-job-rename-and-type-coercion-land-in-output."""
from __future__ import annotations

import csv
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recipe-job-rename-and-type-coercion-land-in-output"
GROUP = "recipe-jobs"
SERVICES = ["databrew"]

INPUT_CSV = (
    "id,employee_name,dept,salary,bonus\n"
    "1,alice,eng,120000,5000\n"
    "2,bob,sales,55000,1000\n"
    "3,carol,eng,98000,2500\n"
    "4,dan,sales,41000,900\n"
    "5,erin,eng,150000,abc\n"
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A recipe job's single output object has `full_name` and no `employee_name` in its header (RENAME), and
    CHANGE_DATA_TYPE to int nulls row 5's non-numeric bonus while keeping the row and its other columns:
    the five bonus values match exactly, ending in the empty field."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    db = ctx.client("databrew")

    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="in/people.csv", Body=INPUT_CSV.encode())
    role_arn = _databrew_role(ctx, iam, bucket)

    dataset = ctx.unique_name("sim2real-behav-databrew-ds-")
    db.create_dataset(
        Name=dataset,
        Format="CSV",
        FormatOptions={"Csv": {"Delimiter": ",", "HeaderRow": True}},
        Input={"S3InputDefinition": {"Bucket": bucket, "Key": "in/people.csv"}},
    )
    ctx.on_cleanup(lambda: db.delete_dataset(Name=dataset))

    recipe = ctx.unique_name("sim2real-behav-databrew-rc-")
    db.create_recipe(
        Name=recipe,
        Description="rename a column and coerce another to int",
        Steps=[
            {
                "Action": {
                    "Operation": "RENAME",
                    "Parameters": {"sourceColumn": "employee_name", "targetColumn": "full_name"},
                }
            },
            {
                "Action": {
                    "Operation": "CHANGE_DATA_TYPE",
                    "Parameters": {"sourceColumn": "bonus", "columnDataType": "int"},
                }
            },
        ],
    )
    ctx.on_cleanup(lambda: _delete_recipe(db, recipe))
    db.publish_recipe(Name=recipe, Description="v1")
    version = db.describe_recipe(Name=recipe)["RecipeVersion"]

    job = ctx.unique_name("sim2real-behav-databrew-job-")
    prefix = "out/"
    _retry_trust(
        lambda: db.create_recipe_job(
            Name=job,
            DatasetName=dataset,
            RoleArn=role_arn,
            LogSubscription="DISABLE",
            Timeout=30,
            MaxRetries=0,
            RecipeReference={"Name": recipe, "RecipeVersion": version},
            Outputs=[
                {
                    "Format": "CSV",
                    "Location": {"Bucket": bucket, "Key": prefix},
                    "Overwrite": True,
                    "MaxOutputFiles": 1,
                }
            ],
        )
    )
    ctx.on_cleanup(lambda: db.delete_job(Name=job))

    run_id = db.start_job_run(Name=job)["RunId"]
    finished = _wait_run(db, job, run_id)
    if finished["State"] != "SUCCEEDED":
        raise AssertionError(
            f"recipe job {job} ended {finished['State']}, not SUCCEEDED: "
            f"{finished.get('ErrorMessage')!r}"
        )

    keys = _keys(s3, bucket, prefix)
    expected_keys = [f"{prefix}{job}_part00000.csv"]
    if keys != expected_keys:
        raise AssertionError(f"output layout was {keys}, expected exactly {expected_keys}")

    header, rows = _read_csv(s3, bucket, keys[0])
    if header != ["id", "full_name", "dept", "salary", "bonus"]:
        raise AssertionError(f"RENAME did not reshape the output header; got {header}")
    if "employee_name" in header:
        raise AssertionError(f"RENAME left the source column in place; got {header}")

    if [r["id"] for r in rows] != ["1", "2", "3", "4", "5"]:
        raise AssertionError(
            f"CHANGE_DATA_TYPE must retain every row; got ids {[r['id'] for r in rows]}"
        )
    if [r["bonus"] for r in rows] != ["5000", "1000", "2500", "900", ""]:
        raise AssertionError(
            f"coercion to int did not null exactly the uncoercible cell; "
            f"bonus values were {[r['bonus'] for r in rows]}"
        )

    # The row whose cell was nulled must otherwise be untouched -- coercion nulls one field,
    # it does not degrade the record.
    row5 = rows[4]
    if row5 != {"id": "5", "full_name": "erin", "dept": "eng", "salary": "150000", "bonus": ""}:
        raise AssertionError(f"the coerced row lost unrelated columns: {row5}")


_ROLE_POLICY = "sim2real-behav-databrew-s3"


def _bucket(ctx, s3):
    """A bucket owned by this check, emptied and removed on cleanup."""
    name = ctx.unique_name("sim2real-behav-databrew-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _databrew_role(ctx, iam, bucket):
    """A role DataBrew can assume, permitted on exactly the bucket this check created."""
    name = ctx.unique_name("sim2real-behav-databrew-role-")
    arn = iam.create_role(
        RoleName=name,
        Description="sim2real-behav databrew data access role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "databrew.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    # Registered before the policy it contains, so the LIFO cleanup deletes the policy first.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName=_ROLE_POLICY,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:DeleteObject",
                            "s3:ListBucket",
                            "s3:GetBucketLocation",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=_ROLE_POLICY))
    return arn


def _retry_trust(fn, budget=120):
    """IAM exposes no condition reporting that a role has become assumable by a service, so the
    only correct form is a bounded retry at first USE of the role -- never a fixed sleep."""
    deadline = time.time() + budget
    while True:
        try:
            return fn()
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            propagating = "not a trusted entity" in message or "when calling s3:GetObject" in message
            if not propagating or time.time() > deadline:
                raise
            time.sleep(5)


def _wait_run(db, job, run_id, budget=210):
    terminal = ("SUCCEEDED", "FAILED", "TIMEOUT", "STOPPED")
    deadline = time.time() + budget
    while True:
        got = db.describe_job_run(Name=job, RunId=run_id)
        if got["State"] in terminal:
            return got
        if time.time() > deadline:
            raise AssertionError(
                f"job run {job}/{run_id} never reached a terminal state within {budget}s; "
                f"last state {got['State']}"
            )
        time.sleep(2)


def _keys(s3, bucket, prefix):
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
        out.extend(o["Key"] for o in page.get("Contents", []))
    return sorted(out)


def _read_csv(s3, bucket, key):
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode()
    reader = csv.DictReader(io.StringIO(body))
    return list(reader.fieldnames or []), [dict(r) for r in reader]


def _delete_recipe(db, name):
    """BatchDeleteRecipeVersion answers HTTP 200 with a per-item `Errors` array instead of
    raising, and refuses LATEST_WORKING while any published version survives -- so published
    versions go first and the per-item result is READ rather than assumed. A cleanup that
    ignored this is exactly how a recipe leaks."""
    published = [
        r["RecipeVersion"]
        for page in db.get_paginator("list_recipe_versions").paginate(Name=name)
        for r in page.get("Recipes", [])
    ]
    for version in published:
        db.batch_delete_recipe_version(Name=name, RecipeVersions=[version])
    errors = db.batch_delete_recipe_version(
        Name=name, RecipeVersions=["LATEST_WORKING"]
    ).get("Errors") or []
    if errors:
        raise AssertionError(f"recipe {name} was not removed: {errors}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
