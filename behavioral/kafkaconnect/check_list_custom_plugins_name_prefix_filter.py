"""list-custom-plugins-name-prefix-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-custom-plugins-name-prefix-filter"
GROUP = "listing"
SERVICES = ["kafkaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomPlugins(namePrefix=...) returns only plugins whose name starts with that prefix."""
    s3 = ctx.client("s3")
    kc = ctx.client("kafkaconnect")

    bucket = ctx.unique_name("sim2real-kc-prefix-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "plugin.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_minimal_plugin_zip_bytes())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    location = {"s3Location": {"bucketArn": f"arn:aws:s3:::{bucket}", "fileKey": key}}

    prefix_a = ctx.unique_name("sim2real-kc-pfxA-")
    prefix_b = ctx.unique_name("sim2real-kc-pfxB-")
    name_a = prefix_a + "plugin"
    name_b = prefix_b + "plugin"

    plugin_tags = {"sim2real:managed": "true"}
    arn_a = kc.create_custom_plugin(
        name=name_a, contentType="ZIP", location=location, tags=plugin_tags
    )["customPluginArn"]
    ctx.on_cleanup(lambda: kc.delete_custom_plugin(customPluginArn=arn_a))
    arn_b = kc.create_custom_plugin(
        name=name_b, contentType="ZIP", location=location, tags=plugin_tags
    )["customPluginArn"]
    ctx.on_cleanup(lambda: kc.delete_custom_plugin(customPluginArn=arn_b))

    filtered = kc.list_custom_plugins(namePrefix=prefix_a)["customPlugins"]
    names = {p["name"] for p in filtered}
    assert name_a in names, names
    assert name_b not in names, names


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
