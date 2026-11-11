"""tags-unicode-value-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tags-unicode-value-round-trip"
GROUP = "error-semantics"
SERVICES = ["redshift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag key/value containing unicode, and an intentionally empty-string
    value, survive CreateTags/DescribeTags byte-for-byte -- an empty string
    value must be distinguishable from the tag being absent."""
    redshift = ctx.client("redshift")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    region = ctx.region

    group_name = ctx.unique_name("sim2real-tagrt-pg-").lower()
    redshift.create_cluster_parameter_group(
        ParameterGroupName=group_name,
        ParameterGroupFamily="redshift-1.0",
        Description="sim2real unicode tag round trip",
    )
    ctx.on_cleanup(lambda: redshift.delete_cluster_parameter_group(ParameterGroupName=group_name))

    resource_arn = f"arn:aws:redshift:{region}:{account}:parametergroup:{group_name}"

    # Redshift tags restrict keys/values to unicode letters, digits, whitespace, and
    # a small punctuation set (+ - = . _ : / @) -- symbols/emoji (not "letters") are
    # rejected with InvalidTagFault, so unicode coverage here uses only accented
    # Latin, Cyrillic, and CJK *letters* plus digits, which ARE permitted.
    unicode_key = "ünïcødé-鍵-clé"
    plain_key = "sim2real-plain"
    unicode_value = "日本語-3.14159-café-Привет"

    redshift.create_tags(
        ResourceName=resource_arn,
        Tags=[
            {"Key": unicode_key, "Value": ""},
            {"Key": plain_key, "Value": unicode_value},
        ],
    )

    tagged = redshift.describe_tags(ResourceName=resource_arn)["TaggedResources"]
    by_key = {t["Tag"]["Key"]: t["Tag"]["Value"] for t in tagged}

    assert unicode_key in by_key, "unicode tag key did not round-trip"
    assert by_key[unicode_key] == "", "empty-string tag value was not preserved exactly"
    assert by_key[plain_key] == unicode_value, "unicode tag value was mangled"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
