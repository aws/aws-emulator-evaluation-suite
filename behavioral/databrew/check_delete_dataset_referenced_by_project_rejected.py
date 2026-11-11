"""delete-dataset-referenced-by-project-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-dataset-referenced-by-project-rejected"
GROUP = "projects"
SERVICES = ["databrew"]

INPUT_CSV = "id,employee_name,dept,salary\n1,alice,eng,120000\n2,bob,sales,55000\n"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While a project holds them, DeleteDataset fails with ConflictException naming the project (the dataset
    still describes), CreateProject reusing the recipe fails with ConflictException, and BatchDeleteRecipeVersion
    reports ErrorCode "409" inside a 200; after DeleteProject, DeleteDataset and the recipe delete succeed."""
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
    ctx.on_cleanup(lambda: _ignore_missing(lambda: db.delete_dataset(Name=dataset)))

    recipe = ctx.unique_name("sim2real-behav-databrew-rc-")
    db.create_recipe(
        Name=recipe,
        Description="attached to a project",
        Steps=[{"Action": {"Operation": "UPPER_CASE", "Parameters": {"sourceColumn": "dept"}}}],
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: _delete_recipe(db, recipe)))

    project = ctx.unique_name("sim2real-behav-databrew-prj-")
    _retry_trust(
        lambda: db.create_project(
            Name=project,
            DatasetName=dataset,
            RecipeName=recipe,
            RoleArn=role_arn,
            Sample={"Size": 500, "Type": "FIRST_N"},
        )
    )
    ctx.on_cleanup(lambda: _ignore_missing(lambda: db.delete_project(Name=project)))

    described = db.describe_project(Name=project)
    if described["DatasetName"] != dataset or described["RecipeName"] != recipe:
        raise AssertionError(
            f"the project does not pin what it was created from: "
            f"{described.get('DatasetName')!r}/{described.get('RecipeName')!r}"
        )

    # ---- refusal 1: the pinned dataset cannot be deleted
    code, message = _rejected("DeleteDataset on a dataset a project pins", lambda: db.delete_dataset(Name=dataset))
    if code != "ConflictException":
        raise AssertionError(f"DeleteDataset on a pinned dataset raised {code}: {message!r}")
    expected = (
        f"The dataset {dataset} is used in project {project}. "
        "To delete this dataset, first delete the associated project."
    )
    if message != expected:
        raise AssertionError(f"the refusal does not name the project holding the dataset: {message!r}")
    still = db.describe_dataset(Name=dataset)
    if still["Name"] != dataset:
        raise AssertionError(f"the refused delete still disturbed the dataset: {still!r}")

    # ---- refusal 2: a recipe belongs to at most one project
    second = ctx.unique_name("sim2real-behav-databrew-prj2-")
    code, message = _rejected(
        "CreateProject on an already-attached recipe",
        lambda: db.create_project(
            Name=second,
            DatasetName=dataset,
            RecipeName=recipe,
            RoleArn=role_arn,
            Sample={"Size": 10, "Type": "FIRST_N"},
        ),
    )
    if code != "ConflictException":
        raise AssertionError(f"reusing an attached recipe raised {code}: {message!r}")
    expected = (
        f"The recipe {recipe} is already associated with project {project}. "
        "Choose a recipe that isn't already part of a project."
    )
    if message != expected:
        raise AssertionError(f"unexpected refusal for reusing an attached recipe: {message!r}")
    code, message = _rejected(
        "describing the project that was refused", lambda: db.describe_project(Name=second)
    )
    if code != "ResourceNotFoundException":
        raise AssertionError(f"the refused CreateProject left a project behind; describe gave {code}")
    if message != f"The project {second} wasn't found.":
        raise AssertionError(f"unexpected not-found message for the refused project: {message!r}")

    # ---- refusal 3: the same conflict, reported inside a 200
    errors = db.batch_delete_recipe_version(
        Name=recipe, RecipeVersions=["LATEST_WORKING"]
    ).get("Errors") or []
    if len(errors) != 1 or errors[0].get("ErrorCode") != "409":
        raise AssertionError(
            f"BatchDeleteRecipeVersion on an attached recipe reported {errors}, expected one '409' item"
        )
    expected = f"Recipe {recipe} version LATEST_WORKING are used by project {project}."
    if errors[0].get("ErrorMessage") != expected:
        raise AssertionError(f"the per-item message does not name the project: {errors[0]!r}")

    # ---- the positive control: release the reference and every refusal above turns into a success
    db.delete_project(Name=project)
    db.delete_dataset(Name=dataset)
    code, message = _rejected("describing the deleted dataset", lambda: db.describe_dataset(Name=dataset))
    if code != "ResourceNotFoundException":
        raise AssertionError(f"the dataset still describes after a successful delete; got {code}")
    if message != f"Dataset {dataset} wasn't found.":
        raise AssertionError(f"unexpected not-found message for the deleted dataset: {message!r}")
    errors = db.batch_delete_recipe_version(
        Name=recipe, RecipeVersions=["LATEST_WORKING"]
    ).get("Errors") or []
    if errors:
        raise AssertionError(f"the recipe was still refused after the project was deleted: {errors}")


_ROLE_POLICY = "sim2real-behav-databrew-s3"


def _rejected(label, fn):
    """The (code, message) of the ClientError ``fn`` must raise. An unexpected success is the
    divergence this helper exists to surface, so it raises rather than returning a sentinel."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"{label} was ACCEPTED, but real AWS rejects it")


def _ignore_missing(fn):
    """For resources this check deletes itself as an assertion: gone is the desired end state,
    so only a NOT-FOUND is tolerated here -- any other cleanup failure still surfaces."""
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


def _delete_recipe(db, name):
    """BatchDeleteRecipeVersion answers HTTP 200 with a per-item `Errors` array instead of
    raising, and refuses LATEST_WORKING while any published version survives -- so published
    versions go first and the per-item result is READ rather than assumed."""
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
    if errors and not all((e.get("ErrorCode") == "404") for e in errors):
        raise AssertionError(f"recipe {name} was not removed: {errors}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
