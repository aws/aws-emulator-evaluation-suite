"""list-tags-for-resource-reflects-creation-time-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-creation-time-tags"
GROUP = "tagging"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied inline to CreateCustomPlugin are visible via ListTagsForResource without a TagResource call."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-createtags-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    plugin_arn = kc.create_custom_plugin(
        name=ctx.unique_name("sim2real-kc-createtags-plugin-"),
        contentType="ZIP",
        location={"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}},
        tags={"Team": "data-platform"},
    )["customPluginArn"]
    ctx.on_cleanup(lambda: kc.delete_custom_plugin(customPluginArn=plugin_arn))

    tags = kc.list_tags_for_resource(resourceArn=plugin_arn)["tags"]
    assert tags == {"Team": "data-platform"}, tags


def _minimal_plugin_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
