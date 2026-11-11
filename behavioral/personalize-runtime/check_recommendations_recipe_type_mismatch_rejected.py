"""recommendations-recipe-type-mismatch-rejected."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "recommendations-recipe-type-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["personalize-runtime"]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On an ACTIVE USER_PERSONALIZATION campaign, GetRecommendations succeeds (positive control) while the
    two runtime operations for other recipe types are rejected with InvalidInputException."""
    rt = ctx.client("personalize-runtime")
    campaign = _build_campaign(ctx, recipe_arn="arn:aws:personalize:::recipe/aws-user-personalization")
    campaign_arn = campaign["campaign_arn"]
    known_user = campaign["users"][0]
    some_items = campaign["items"][:5]

    # positive control: the campaign is real, ACTIVE, and correctly backed by
    # USER_PERSONALIZATION -- the matching operation succeeds.
    resp = rt.get_recommendations(campaignArn=campaign_arn, userId=known_user, numResults=5)
    assert len(resp["itemList"]) >= 1
    assert resp["recommendationId"]

    # negative 1: GetPersonalizedRanking requires a PERSONALIZED_RANKING recipe.
    code = _error_code(
        lambda: rt.get_personalized_ranking(campaignArn=campaign_arn, userId=known_user, inputList=some_items)
    )
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"

    # negative 2: GetActionRecommendations requires a PERSONALIZED_ACTIONS recipe.
    code = _error_code(lambda: rt.get_action_recommendations(campaignArn=campaign_arn, userId=known_user))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"

    # the campaign is untouched by the rejected calls: the matching operation still works.
    resp2 = rt.get_recommendations(campaignArn=campaign_arn, userId=known_user, numResults=5)
    assert len(resp2["itemList"]) >= 1
    assert resp2["recommendationId"]


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until_status(get_status, active_values, failure_values, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = get_status()
        if last in active_values:
            return last
        if last in failure_values:
            raise AssertionError(f"{description} entered failure status {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"{description} did not reach {active_values} within {timeout_s}s (last status {last!r})")


def _delete_and_wait_gone(describe_fn, delete_fn, timeout_s=600, interval_s=15):
    for _ in range(3):
        try:
            delete_fn()
            break
        except Exception:
            time.sleep(interval_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            describe_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        time.sleep(interval_s)


def _create_import_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-personalize-").lower().replace("_", "-")
    region = ctx.region
    # not a region pin: S3's CreateBucket rejects an explicit LocationConstraint for us-east-1,
    # so the literal only selects which call shape matches ctx.region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    role_name = ctx.unique_name("sim2real-personalize-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "personalize.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PersonalizeS3BucketAccessPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "personalize.amazonaws.com"},
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))
    return {"bucket": bucket, "role_arn": role_arn, "role_name": role_name}


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _generate_interactions_csv(num_users=40, num_items=50, seed=555):
    rng = random.Random(seed)
    users = [f"user{i}" for i in range(num_users)]
    items = [f"item{i}" for i in range(num_items)]
    now = int(time.time())
    rows = ["USER_ID,ITEM_ID,EVENT_TYPE,TIMESTAMP"]
    for u in users:
        k = rng.randint(25, min(35, num_items))
        chosen = rng.sample(items, k)
        for it in chosen:
            ts = now - rng.randint(0, 180 * 24 * 3600)
            event = rng.choice(["click", "view"])
            rows.append(f"{u},{it},{event},{ts}")
    return "\n".join(rows), users, items


def _create_import_job_with_retry(ctx, personalize, job_name, dataset_arn, s3_uri, role_arn):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(8):
        try:
            resp = personalize.create_dataset_import_job(
                jobName=job_name,
                datasetArn=dataset_arn,
                dataSource={"dataLocation": s3_uri},
                roleArn=role_arn,
                importMode="FULL",
            )
            return resp["datasetImportJobArn"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(10)
    raise last_exc


def _create_interactions_pipeline_stage1(ctx, csv_body, role_arn, bucket):
    personalize = ctx.client("personalize")
    s3 = ctx.client("s3")
    key = "interactions.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=csv_body.encode("utf-8"))

    schema = {
        "type": "record",
        "name": "Interactions",
        "namespace": "com.amazonaws.personalize.schema",
        "fields": [
            {"name": "USER_ID", "type": "string"},
            {"name": "ITEM_ID", "type": "string"},
            {"name": "EVENT_TYPE", "type": "string"},
            {"name": "TIMESTAMP", "type": "long"},
        ],
        "version": "1.0",
    }
    schema_name = ctx.unique_name("sim2real-personalize-schema-")
    schema_arn = personalize.create_schema(name=schema_name, schema=json.dumps(schema))["schemaArn"]
    ctx.on_cleanup(
        lambda: _delete_and_wait_gone(
            lambda: personalize.describe_schema(schemaArn=schema_arn),
            lambda: personalize.delete_schema(schemaArn=schema_arn),
            timeout_s=120,
            interval_s=10,
        )
    )

    dsg_name = ctx.unique_name("sim2real-personalize-dsg-")
    dsg_arn = personalize.create_dataset_group(
        name=dsg_name, tags=[{"tagKey": "sim2real", "tagValue": CHECK}]
    )["datasetGroupArn"]
    ctx.on_cleanup(
        lambda: _delete_and_wait_gone(
            lambda: personalize.describe_dataset_group(datasetGroupArn=dsg_arn),
            lambda: personalize.delete_dataset_group(datasetGroupArn=dsg_arn),
            timeout_s=600,
            interval_s=15,
        )
    )
    _poll_until_status(
        lambda: personalize.describe_dataset_group(datasetGroupArn=dsg_arn)["datasetGroup"]["status"],
        {"ACTIVE"},
        {"CREATE FAILED"},
        300,
        5,
        "dataset group",
    )

    dataset_name = ctx.unique_name("sim2real-personalize-ds-")
    dataset_arn = personalize.create_dataset(
        name=dataset_name,
        schemaArn=schema_arn,
        datasetGroupArn=dsg_arn,
        datasetType="Interactions",
        tags=[{"tagKey": "sim2real", "tagValue": CHECK}],
    )["datasetArn"]
    ctx.on_cleanup(
        lambda: _delete_and_wait_gone(
            lambda: personalize.describe_dataset(datasetArn=dataset_arn),
            lambda: personalize.delete_dataset(datasetArn=dataset_arn),
            timeout_s=300,
            interval_s=15,
        )
    )

    job_name = ctx.unique_name("sim2real-personalize-import-")
    s3_uri = f"s3://{bucket}/{key}"
    import_job_arn = _create_import_job_with_retry(ctx, personalize, job_name, dataset_arn, s3_uri, role_arn)
    _poll_until_status(
        lambda: personalize.describe_dataset_import_job(datasetImportJobArn=import_job_arn)["datasetImportJob"][
            "status"
        ],
        {"ACTIVE"},
        {"CREATE FAILED"},
        1800,
        20,
        "dataset import job",
    )
    return {"dataset_group_arn": dsg_arn, "dataset_arn": dataset_arn}


def _train_solution(ctx, dataset_group_arn, recipe_arn):
    personalize = ctx.client("personalize")
    solution_name = ctx.unique_name("sim2real-personalize-sol-")
    solution_arn = personalize.create_solution(
        name=solution_name,
        recipeArn=recipe_arn,
        datasetGroupArn=dataset_group_arn,
        performHPO=False,
        performAutoML=False,
        tags=[{"tagKey": "sim2real", "tagValue": CHECK}],
    )["solutionArn"]
    ctx.on_cleanup(
        lambda: _delete_and_wait_gone(
            lambda: personalize.describe_solution(solutionArn=solution_arn),
            lambda: personalize.delete_solution(solutionArn=solution_arn),
            timeout_s=900,
            interval_s=20,
        )
    )
    solution_version_arn = personalize.create_solution_version(solutionArn=solution_arn)["solutionVersionArn"]
    _poll_until_status(
        lambda: personalize.describe_solution_version(solutionVersionArn=solution_version_arn)["solutionVersion"][
            "status"
        ],
        {"ACTIVE"},
        {"CREATE FAILED"},
        7200,
        60,
        "solution version training",
    )
    return solution_arn, solution_version_arn


def _deploy_campaign(ctx, solution_version_arn):
    personalize = ctx.client("personalize")
    campaign_name = ctx.unique_name("sim2real-personalize-camp-")
    campaign_arn = personalize.create_campaign(
        name=campaign_name,
        solutionVersionArn=solution_version_arn,
        tags=[{"tagKey": "sim2real", "tagValue": CHECK}],
    )["campaignArn"]
    ctx.on_cleanup(
        lambda: _delete_and_wait_gone(
            lambda: personalize.describe_campaign(campaignArn=campaign_arn),
            lambda: personalize.delete_campaign(campaignArn=campaign_arn),
            timeout_s=900,
            interval_s=20,
        )
    )
    _poll_until_status(
        lambda: personalize.describe_campaign(campaignArn=campaign_arn)["campaign"]["status"],
        {"ACTIVE"},
        {"CREATE FAILED"},
        1800,
        20,
        "campaign deployment",
    )
    return campaign_arn


def _build_campaign(ctx, recipe_arn, num_users=40, num_items=50):
    setup = _create_import_role_and_bucket(ctx)
    csv_body, users, items = _generate_interactions_csv(num_users=num_users, num_items=num_items)
    stage1 = _create_interactions_pipeline_stage1(ctx, csv_body, setup["role_arn"], setup["bucket"])
    _, solution_version_arn = _train_solution(ctx, stage1["dataset_group_arn"], recipe_arn)
    campaign_arn = _deploy_campaign(ctx, solution_version_arn)
    return {
        "campaign_arn": campaign_arn,
        "dataset_group_arn": stage1["dataset_group_arn"],
        "users": users,
        "items": items,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
