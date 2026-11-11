"""recipe-job-on-mismatched-dataset-schema-fails-and-writes-nothing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recipe-job-on-mismatched-dataset-schema-fails-and-writes-nothing"
GROUP = "recipe-jobs"
SERVICES = ["databrew"]

GOOD_CSV = (
    "id,employee_name,dept,salary\n"
    "1,alice,eng,120000\n"
    "2,bob,sales,55000\n"
    "3,carol,eng,98000\n"
)
MISMATCHED_CSV = "sku,qty\nA-1,4\nA-2,9\n"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A recipe job over a dataset lacking the recipe's column is admitted (one ListJobRuns run) and ends
    FAILED with a RecipeStepError naming step 1, column 'dept' and the columns sku and qty, writing zero
    objects; a project over the matching dataset with the same role and recipe succeeds."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    db = ctx.client("databrew")

    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="in/people.csv", Body=GOOD_CSV.encode())
    s3.put_object(Bucket=bucket, Key="in/parts.csv", Body=MISMATCHED_CSV.encode())
    role_arn = _databrew_role(ctx, iam, bucket)

    matching = ctx.unique_name("sim2real-behav-databrew-ds-ok-")
    mismatched = ctx.unique_name("sim2real-behav-databrew-ds-bad-")
    for name, key in ((matching, "in/people.csv"), (mismatched, "in/parts.csv")):
        db.create_dataset(
            Name=name,
            Format="CSV",
            FormatOptions={"Csv": {"Delimiter": ",", "HeaderRow": True}},
            Input={"S3InputDefinition": {"Bucket": bucket, "Key": key}},
        )
        ctx.on_cleanup(lambda n=name: db.delete_dataset(Name=n))

    recipe = ctx.unique_name("sim2real-behav-databrew-rc-")
    db.create_recipe(
        Name=recipe,
        Description="references the dept column, which one of the two datasets lacks",
        Steps=[
            {
                "Action": {"Operation": "REMOVE_VALUES", "Parameters": {"sourceColumn": "dept"}},
                "ConditionExpressions": [
                    {"Condition": "IS", "Value": '["sales"]', "TargetColumn": "dept"}
                ],
            }
        ],
    )
    ctx.on_cleanup(lambda: _delete_recipe(db, recipe))

    # ---- the positive control: role, bucket, dataset and recipe are all sound together
    project = ctx.unique_name("sim2real-behav-databrew-prj-")
    _retry_trust(
        lambda: db.create_project(
            Name=project,
            DatasetName=matching,
            RecipeName=recipe,
            RoleArn=role_arn,
            Sample={"Size": 500, "Type": "FIRST_N"},
        )
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: db.delete_project(Name=project)))
    bound = db.describe_project(Name=project)
    if bound["DatasetName"] != matching or bound["RecipeName"] != recipe:
        raise AssertionError(f"the control project did not bind what it was given: {bound!r}")
    if bound["RoleArn"] != role_arn:
        raise AssertionError(f"the control project did not bind the role: {bound.get('RoleArn')!r}")
    # Released immediately: a project pins the recipe's draft, and the job below needs to publish it.
    db.delete_project(Name=project)

    db.publish_recipe(Name=recipe, Description="v1")
    version = db.describe_recipe(Name=recipe)["RecipeVersion"]

    job = ctx.unique_name("sim2real-behav-databrew-job-bad-")
    prefix = "out-mismatch/"
    _retry_trust(
        lambda: db.create_recipe_job(
            Name=job,
            DatasetName=mismatched,
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

    if finished["State"] != "FAILED":
        raise AssertionError(
            f"a recipe job over a mismatched schema ended {finished['State']}, expected FAILED "
            f"(ErrorMessage {finished.get('ErrorMessage')!r})"
        )
    reason = finished.get("ErrorMessage") or ""
    if not reason.startswith("RecipeStepError"):
        raise AssertionError(f"the failure reason is not a RecipeStepError: {reason!r}")
    if "Failed at step 1" not in reason:
        raise AssertionError(f"the failure reason does not name the failing step: {reason!r}")
    if "Column 'dept' does not exist" not in reason:
        raise AssertionError(f"the failure reason does not name the missing column: {reason!r}")
    if "qty" not in reason or "sku" not in reason:
        raise AssertionError(
            f"the failure reason does not enumerate the columns the dataset does have: {reason!r}"
        )

    stray = _keys(s3, bucket, prefix)
    if stray:
        raise AssertionError(f"a FAILED recipe job wrote output anyway: {stray}")

    # The run was admitted and executed -- FAILED is not a rejection at the door.
    runs = [
        r["RunId"]
        for page in db.get_paginator("list_job_runs").paginate(Name=job)
        for r in page.get("JobRuns", [])
    ]
    if runs != [run_id]:
        raise AssertionError(f"ListJobRuns reported {runs}, expected exactly [{run_id!r}]")


_ROLE_POLICY = "sim2real-behav-databrew-s3"


def _ignore_missing(fn):
    """For a resource this check deletes itself as part of the scenario: gone is the desired end
    state, so only a NOT-FOUND is tolerated -- any other cleanup failure still surfaces."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "ResourceNotFoundException",
            "NotFoundException",
        ):
            raise


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
    """IAM exposes no condition reporting that a role has become assumable by a service, and
    CreateProject reads the dataset's S3 location THROUGH that role, so the only correct form is
    a bounded retry at first use -- never a fixed sleep."""
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
    """Deliberately below the runner's per-check ceiling: exceeding this budget raises and still
    runs the registered cleanups, whereas being killed by the ceiling leaks every resource."""
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
