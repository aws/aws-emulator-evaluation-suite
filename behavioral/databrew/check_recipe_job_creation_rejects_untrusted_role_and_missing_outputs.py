"""recipe-job-creation-rejects-untrusted-role-and-missing-outputs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recipe-job-creation-rejects-untrusted-role-and-missing-outputs"
GROUP = "recipe-jobs"
SERVICES = ["databrew"]

INPUT_CSV = "id,employee_name,dept,salary\n1,alice,eng,120000\n2,bob,sales,55000\n"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRecipeJob fails with ValidationException for a role DataBrew cannot assume, without Outputs, and
    with ConflictException for a duplicate name, minting no job; a valid job describes with MaxCapacity 5 and
    Type RECIPE, and StartJobRun and DeleteJob on an unknown name fail with ResourceNotFoundException."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    db = ctx.client("databrew")

    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="in/people.csv", Body=INPUT_CSV.encode())
    role_arn = _databrew_role(ctx, iam, bucket, "databrew.amazonaws.com", "-role-")
    wrong_role_arn = _databrew_role(ctx, iam, bucket, "lambda.amazonaws.com", "-wrongrole-")

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
        Description="upper-cases one column",
        Steps=[{"Action": {"Operation": "UPPER_CASE", "Parameters": {"sourceColumn": "dept"}}}],
    )
    ctx.on_cleanup(lambda: _delete_recipe(db, recipe))
    db.publish_recipe(Name=recipe, Description="v1")
    version = db.describe_recipe(Name=recipe)["RecipeVersion"]
    reference = {"Name": recipe, "RecipeVersion": version}
    outputs = [
        {
            "Format": "CSV",
            "Location": {"Bucket": bucket, "Key": "out/"},
            "Overwrite": True,
            "MaxOutputFiles": 1,
        }
    ]

    # ---- rejection 1: a role that exists but DataBrew cannot assume
    untrusted = ctx.unique_name("sim2real-behav-databrew-job-untrusted-")
    code, message = _rejected(
        "CreateRecipeJob with a role DataBrew cannot assume",
        lambda: db.create_recipe_job(
            Name=untrusted,
            DatasetName=dataset,
            RoleArn=wrong_role_arn,
            RecipeReference=reference,
            Outputs=outputs,
        ),
    )
    if code != "ValidationException":
        raise AssertionError(f"an untrusted role raised {code}: {message!r}")
    if "DataBrew is not a trusted entity for the data access role" not in message:
        raise AssertionError(f"unexpected refusal for an untrusted role: {message!r}")
    if wrong_role_arn not in message:
        raise AssertionError(f"the refusal does not name the role it rejected: {message!r}")
    _must_not_exist(db, untrusted, "the job created with an untrusted role")

    # ---- rejection 2: no Outputs at all
    no_outputs = ctx.unique_name("sim2real-behav-databrew-job-noout-")
    code, message = _rejected(
        "CreateRecipeJob with no Outputs",
        lambda: db.create_recipe_job(
            Name=no_outputs, DatasetName=dataset, RoleArn=role_arn, RecipeReference=reference
        ),
    )
    if code != "ValidationException":
        raise AssertionError(f"a job with no Outputs raised {code}: {message!r}")
    if message != "No outputs were selected for this job.":
        raise AssertionError(f"unexpected refusal for a job with no Outputs: {message!r}")
    _must_not_exist(db, no_outputs, "the job created with no Outputs")

    # ---- the positive control, and the defaults the service materialises
    job = ctx.unique_name("sim2real-behav-databrew-job-")
    _retry_trust(
        lambda: db.create_recipe_job(
            Name=job,
            DatasetName=dataset,
            RoleArn=role_arn,
            LogSubscription="DISABLE",
            Timeout=30,
            MaxRetries=0,
            RecipeReference=reference,
            Outputs=outputs,
        )
    )
    ctx.on_cleanup(lambda: db.delete_job(Name=job))
    described = db.describe_job(Name=job)
    if described["Type"] != "RECIPE":
        raise AssertionError(f"DescribeJob reports Type {described['Type']!r}, expected 'RECIPE'")
    if described.get("MaxCapacity") != 5:
        raise AssertionError(
            f"a job that never set MaxCapacity reports {described.get('MaxCapacity')!r}, "
            f"expected the service default of 5"
        )
    if described.get("Timeout") != 30:
        raise AssertionError(f"DescribeJob did not echo the Timeout: {described.get('Timeout')!r}")
    if described["RecipeReference"] != reference:
        raise AssertionError(f"DescribeJob did not echo the recipe reference: {described['RecipeReference']!r}")

    # ---- rejection 3: the name is now claimed
    code, message = _rejected(
        "CreateRecipeJob on an existing name",
        lambda: db.create_recipe_job(
            Name=job, DatasetName=dataset, RoleArn=role_arn, RecipeReference=reference, Outputs=outputs
        ),
    )
    if code != "ConflictException":
        raise AssertionError(f"a duplicate job name raised {code}: {message!r}")
    if "already exists" not in message:
        raise AssertionError(f"unexpected refusal for a duplicate job name: {message!r}")
    if db.describe_job(Name=job).get("Timeout") != 30:
        raise AssertionError("the refused duplicate create overwrote the existing job")

    # ---- an absent job is absent to every verb, not only to DescribeJob
    absent = ctx.unique_name("sim2real-behav-databrew-absent-")
    for label, call in (
        ("StartJobRun", lambda: db.start_job_run(Name=absent)),
        ("DeleteJob", lambda: db.delete_job(Name=absent)),
        ("DescribeJob", lambda: db.describe_job(Name=absent)),
    ):
        code, message = _rejected(f"{label} on a job that does not exist", call)
        if code != "ResourceNotFoundException":
            raise AssertionError(f"{label} on a missing job raised {code}: {message!r}")
        if absent not in message:
            raise AssertionError(f"{label} does not name the missing job: {message!r}")


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


def _must_not_exist(db, job, label):
    try:
        db.describe_job(Name=job)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    raise AssertionError(f"{label} was refused, yet the job exists")


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


def _databrew_role(ctx, iam, bucket, trust_service, label):
    """A role trusting ``trust_service``, permitted on exactly the bucket this check created.
    Parameterised on the trusted principal so the WRONG-trust role this check needs is minted
    here too, rather than borrowed from whatever the account happens to contain."""
    name = ctx.unique_name(f"sim2real-behav-databrew{label}")
    arn = iam.create_role(
        RoleName=name,
        Description="sim2real-behav databrew data access role",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trust_service},
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
    if errors:
        raise AssertionError(f"recipe {name} was not removed: {errors}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
