"""directory-bucket-rejects-object-tagging-versioning-notification-and-replication."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "directory-bucket-rejects-object-tagging-versioning-notification-and-replication"
GROUP = "directory-bucket-unsupported-config"
SERVICES = ["s3"]

# S3 Express One Zone Availability-Zone IDs per region. Zone IDs (not names) are physical and
# identical in every account, so this table holds for any account.
_S3EXPRESS_AZ_IDS = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


def _empty_and_delete_directory_bucket(s3, bucket):
    """Directory buckets support neither versioning nor ListObjectVersions."""
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _empty_and_delete_versioned_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in (page.get("Versions") or []) + (page.get("DeleteMarkers") or []):
            s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _directory_bucket(ctx, s3, prefix):
    """Create an S3 Express directory bucket, registering its teardown in the same breath."""
    azs = _S3EXPRESS_AZ_IDS.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region!r}")
    base = ctx.unique_name(prefix)
    last = None
    for az in azs:
        name = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda b=name: _empty_and_delete_directory_bucket(s3, b))
        return name
    raise AssertionError(f"could not create a directory bucket in any of {azs!r}: {last}")


def _general_purpose_bucket(ctx, s3, prefix):
    name = ctx.unique_name(prefix)
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_versioned_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:control", "plane:data")
def run(ctx) -> None:
    """A directory bucket refuses PutObjectTagging, PutBucketVersioning,
    PutBucketNotificationConfiguration and PutBucketReplication with their exact errors, while a
    general-purpose twin accepts the same tagging, versioning and notification calls."""
    s3 = ctx.client("s3")
    directory = _directory_bucket(ctx, s3, "sim2real-s3x-cfg-")
    twin = _general_purpose_bucket(ctx, s3, "sim2real-s3x-cfg-gp-")
    s3.put_object(Bucket=directory, Key="a.txt", Body=b"hi")
    s3.put_object(Bucket=twin, Key="a.txt", Body=b"hi")

    code, message = _error(lambda: s3.put_object_tagging(
        Bucket=directory, Key="a.txt", Tagging={"TagSet": [{"Key": "k", "Value": "v"}]}))
    assert (code, message) == ("NotImplemented", "This bucket does not support Object Tags."), (
        f"PutObjectTagging on a directory bucket returned {(code, message)!r}"
    )
    s3.put_object_tagging(Bucket=twin, Key="a.txt", Tagging={"TagSet": [{"Key": "k", "Value": "v"}]})
    twin_tags = sorted((t["Key"], t["Value"]) for t in s3.get_object_tagging(Bucket=twin, Key="a.txt")["TagSet"])
    assert twin_tags == [("k", "v")], f"the general-purpose twin's tag did not land: {twin_tags!r}"

    code, message = _error(lambda: s3.put_bucket_versioning(
        Bucket=directory, VersioningConfiguration={"Status": "Enabled"}))
    assert (code, message) == (
        "InvalidArgument", "VersioningConfiguration is not valid, expected CreateBucketConfiguration"
    ), f"PutBucketVersioning on a directory bucket returned {(code, message)!r}"
    s3.put_bucket_versioning(Bucket=twin, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=twin).get("Status") == "Enabled", (
        "the general-purpose twin's PutBucketVersioning did not take effect"
    )

    code, message = _error(lambda: s3.put_bucket_notification_configuration(
        Bucket=directory, NotificationConfiguration={}))
    assert (code, message) == (
        "InvalidArgument", "NotificationConfiguration is not valid, expected CreateBucketConfiguration"
    ), f"PutBucketNotificationConfiguration on a directory bucket returned {(code, message)!r}"
    s3.put_bucket_notification_configuration(Bucket=twin, NotificationConfiguration={})
    twin_notification = s3.get_bucket_notification_configuration(Bucket=twin)
    configured = sorted(k for k in twin_notification if k.endswith("Configurations"))
    assert configured == [], (
        f"the general-purpose twin's empty notification configuration read back {configured!r}"
    )

    code, message = _error(lambda: s3.put_bucket_replication(
        Bucket=directory,
        ReplicationConfiguration={
            "Role": f"arn:aws:iam::{ctx.account}:role/sim2real-does-not-need-to-exist",
            "Rules": [{
                "ID": "r1", "Status": "Enabled", "Priority": 1,
                "DeleteMarkerReplication": {"Status": "Disabled"},
                "Filter": {"Prefix": ""},
                "Destination": {"Bucket": f"arn:aws:s3:::{ctx.unique_name('sim2real-s3x-cfg-dest-')}"},
            }],
        },
    ))
    assert (code, message) == (
        "InvalidArgument", "ReplicationConfiguration is not valid, expected CreateBucketConfiguration"
    ), f"PutBucketReplication on a directory bucket returned {(code, message)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
