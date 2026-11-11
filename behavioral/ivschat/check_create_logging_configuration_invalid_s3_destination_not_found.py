"""create-logging-configuration-invalid-s3-destination-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-logging-configuration-invalid-s3-destination-not-found"
GROUP = "errors"
SERVICES = ["ivschat"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _empty_and_delete(s3, bucket):
    from botocore.exceptions import ClientError

    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLoggingConfiguration on a missing S3 bucket fails ResourceNotFoundException with the exact message and
    leaves no configuration listed, while an existing bucket is accepted."""
    ivschat = ctx.client("ivschat")
    s3 = ctx.client("s3")

    good_bucket = ctx.unique_name("sim2real-ivschat-goodlogcfg-").lower()
    create_kwargs = {"Bucket": good_bucket}
    # S3 CreateBucket quirk, not a region pin: us-east-1 rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete(s3, good_bucket))
    s3.put_bucket_tagging(
        Bucket=good_bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "ivschat-badlogcfg-control"}]},
    )

    good_name = ctx.unique_name("sim2real-ivschat-goodlogcfg")
    good = ivschat.create_logging_configuration(
        name=good_name, destinationConfiguration={"s3": {"bucketName": good_bucket}}
    )
    good_arn = good.get("arn")
    ctx.on_cleanup(lambda: ivschat.delete_logging_configuration(identifier=good_arn))
    assert good_arn, (
        f"positive control: creating a logging configuration against a real, existing bucket "
        f"must succeed and return an arn; got {good!r}"
    )

    name = ctx.unique_name("sim2real-ivschat-badlogcfg")
    raw = ctx.unique_name("sim2real-ivschat-nobucket").lower()
    bogus_bucket = "".join(c if c.isalnum() or c == "-" else "-" for c in raw)[:63]

    code, message = _error_code(
        lambda: ivschat.create_logging_configuration(
            name=name, destinationConfiguration={"s3": {"bucketName": bogus_bucket}}
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Resource: {bogus_bucket} not found", f"unexpected message: {message!r}"

    found = [
        cfg
        for cfg in ivschat.list_logging_configurations().get("loggingConfigurations", [])
        if cfg["name"] == name
    ]
    assert found == [], f"a logging configuration named {name!r} should not exist: {found}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
