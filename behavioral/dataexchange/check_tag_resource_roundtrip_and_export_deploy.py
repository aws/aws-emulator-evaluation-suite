"""tag-resource-roundtrip-and-export-deploy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "tag-resource-roundtrip-and-export-deploy"

GROUP = "deploy"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag/Untag/ListTagsForResource change a data set's stored tag map exactly, and a
    CREATE_S3_DATA_ACCESS_FROM_S3_BUCKET job on an existing bucket and object ends ERROR with a
    VALIDATION_EXCEPTION: the service enforces its s3:GetObject prerequisite at job run time."""

    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    arn = dx.get_data_set(DataSetId=dataset_id)["Arn"]

    initial = dx.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert initial == {}

    dx.tag_resource(ResourceArn=arn, Tags={"sim2real-owner": "behavioral-check", "sim2real-env": "test"})
    after_tag = dx.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_tag == {"sim2real-owner": "behavioral-check", "sim2real-env": "test"}

    dx.untag_resource(ResourceArn=arn, TagKeys=["sim2real-env"])
    after_untag = dx.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_untag == {"sim2real-owner": "behavioral-check"}

    # ---- Deploy workflow: provision a real S3 bucket + object + resource policy, then
    # wire an S3_DATA_ACCESS data set to it ----
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-dx-s3da-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = "sim2real-s3-data-access-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-s3-data-access-payload")

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDataExchangeRead",
                "Effect": "Allow",
                "Principal": {"Service": "dataexchange.amazonaws.com"},
                "Action": ["s3:GetObject", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    s3da_dataset_id = _create_dataset(ctx, dx, asset_type="S3_DATA_ACCESS")
    revision_id = _create_revision(ctx, dx, s3da_dataset_id)

    # S3 bucket policies can take a few seconds to propagate before DataExchange's
    # backend consistently observes them, so retry the job itself -- the operation
    # actually under test -- against a bounded deadline instead of sleeping blind
    # before the first attempt.
    final_state, final = _run_s3_data_access_job_until_error(
        dx, bucket, [key], s3da_dataset_id, revision_id, timeout_s=60.0
    )
    assert final_state == "ERROR", f"expected the job to end in ERROR, got {final_state}: {final.get('Errors')}"
    error_codes = {e["Code"] for e in final.get("Errors", [])}
    assert "VALIDATION_EXCEPTION" in error_codes, final.get("Errors")


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    for obj in objs:
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_dataset(ctx, dx, asset_type: str = "S3_SNAPSHOT") -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(AssetType=asset_type, Description="sim2real check", Name=name)
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(DataSetId=dataset_id, Comment="sim2real revision")
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


def _poll_job_state(dx, job_id: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states and time.monotonic() < deadline:
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    return state


def _run_s3_data_access_job_until_error(
    dx, bucket: str, keys: list, dataset_id: str, revision_id: str,
    timeout_s: float = 60.0, interval_s: float = 5.0,
):
    """Retries CreateJob/StartJob (not a sleep) so a not-yet-propagated bucket
    policy is absorbed by re-attempting the real call under test, bounded by
    timeout_s, rather than guessing a fixed propagation delay up front."""
    deadline = time.monotonic() + timeout_s
    while True:
        job = dx.create_job(
            Type="CREATE_S3_DATA_ACCESS_FROM_S3_BUCKET",
            Details={
                "CreateS3DataAccessFromS3Bucket": {
                    "AssetSource": {"Bucket": bucket, "Keys": keys},
                    "DataSetId": dataset_id,
                    "RevisionId": revision_id,
                }
            },
        )
        job_id = job["Id"]
        assert job["State"] == "WAITING"
        dx.start_job(JobId=job_id)
        final_state = _poll_job_state(dx, job_id, {"COMPLETED", "ERROR", "TIMED_OUT"}, timeout_s=120)
        final = dx.get_job(JobId=job_id)
        if final_state == "ERROR" or time.monotonic() >= deadline:
            return final_state, final
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


