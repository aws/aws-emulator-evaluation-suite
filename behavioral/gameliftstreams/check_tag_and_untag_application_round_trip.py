"""tag-and-untag-application-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-application-round-trip"
GROUP = "control-plane"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/ListTagsForResource/UntagResource round-trip on an application resource."""
    gl = ctx.client("gameliftstreams")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-glsbkt-")
    try:
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
        s3.put_object(Bucket=bucket, Key="build/start.sh", Body=b"#!/bin/sh\necho hi\n")
        ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="build/start.sh"))
    except ClientError as e:
        raise AssertionError(
            f"S3 write access unavailable in this verification session ({e}); cannot "
            "provision real application content for CreateApplication to succeed on"
        )

    created = gl.create_application(
        Description=ctx.unique_name("sim2real-behav-gls-app-"),
        RuntimeEnvironment={"Type": "UBUNTU", "Version": "22_04_LTS"},
        ExecutablePath="start.sh",
        ApplicationSourceUri=f"s3://{bucket}/build",
    )
    arn = created["Arn"]
    ctx.on_cleanup(lambda: gl.delete_application(Identifier=arn))

    before = gl.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert before == {}, f"expected a freshly created application to have no tags, got {before!r}"

    gl.tag_resource(ResourceArn=arn, Tags={"sim2real-env": "test"})
    after_tag = gl.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_tag == {"sim2real-env": "test"}, (
        f"expected exactly {{'sim2real-env': 'test'}} after TagResource, got {after_tag!r}"
    )

    gl.untag_resource(ResourceArn=arn, TagKeys=["sim2real-env"])
    after_untag = gl.list_tags_for_resource(ResourceArn=arn).get("Tags", {})
    assert after_untag == {}, f"expected no tags after UntagResource, got {after_untag!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
