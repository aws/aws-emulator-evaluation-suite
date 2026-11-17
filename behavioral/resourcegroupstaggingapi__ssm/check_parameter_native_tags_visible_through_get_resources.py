"""parameter-native-tags-visible-through-get-resources."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-native-tags-visible-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["resourcegroupstaggingapi", "ssm"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag set on an SSM parameter through PutParameter's Tags list appears in the tagging
    API's GetResources filtered to ssm:parameter, and SSM's own RemoveTagsFromResource removes
    it from that index."""
    ssm = ctx.client("ssm")
    rgt = ctx.client("resourcegroupstaggingapi")

    name = ctx.unique_name("sim2real-behav-param-")
    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")
    expected_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:parameter/{name}"

    ssm.put_parameter(Name=name, Value="sim2real-behav-value", Type="String",
                       Tags=[{"Key": key, "Value": value}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))

    native_tags = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]
    native_pairs = {t["Key"]: t["Value"] for t in native_tags}
    assert native_pairs.get(key) == value, (
        f"ListTagsForResource reported {native_pairs!r}, missing {key}={value!r} that PutParameter set"
    )

    found = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["ssm:parameter"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == expected_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the parameter's own ARN {expected_arn!r}"
    )
    index_pairs = {t["Key"]: t["Value"] for t in found[0]["Tags"]}
    assert index_pairs.get(key) == value, (
        f"tagging-api index reports tags {index_pairs!r}, missing {key}={value!r}"
    )

    ssm.remove_tags_from_resource(ResourceType="Parameter", ResourceId=name, TagKeys=[key])

    gone = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["ssm:parameter"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: mappings == [],
        timeout_s=120.0,
    )
    assert gone == [], (
        f"RemoveTagsFromResource removed {key}={value!r} from SSM's own tag list, but the "
        f"tagging index still reports {gone!r}"
    )

    after_native = ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]
    after_pairs = {t["Key"]: t["Value"] for t in after_native}
    assert key not in after_pairs, (
        f"ListTagsForResource still reports {key!r} after RemoveTagsFromResource: {after_pairs!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
