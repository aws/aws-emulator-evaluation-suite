"""tag-value-unicode-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "representation"
SERVICES = ["servicediscovery"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag key/value pairs containing unicode and a boundary-length value written via
    TagResource are returned unchanged by ListTagsForResource."""
    sd = ctx.client("servicediscovery")
    ns_name = ctx.unique_name("sim2real-behav-ns-")
    namespace_id = _create_http_namespace(ctx, ns_name)
    namespace_arn = sd.get_namespace(Id=namespace_id)["Namespace"]["Arn"]

    unicode_key = "\u30ad\u30fc-key"  # キー-key
    unicode_value = "\u5024-" + ("\u5b57" * 254)  # 値-<254 CJK ideographs> = 256 chars, TagValue's modeled max

    sd.tag_resource(ResourceARN=namespace_arn, Tags=[{"Key": unicode_key, "Value": unicode_value}])
    ctx.on_cleanup(lambda: sd.untag_resource(ResourceARN=namespace_arn, TagKeys=[unicode_key]))

    tags = {t["Key"]: t["Value"] for t in sd.list_tags_for_resource(ResourceARN=namespace_arn)["Tags"]}
    assert unicode_key in tags, f"unicode tag key not round-tripped: {list(tags)}"
    assert tags[unicode_key] == unicode_value, f"tag value mangled: {tags[unicode_key]!r} != {unicode_value!r}"


def _wait_operation(ctx, operation_id: str, timeout_s: float = 240.0, interval_s: float = 3.0) -> dict[str, Any]:
    sd = ctx.client("servicediscovery")
    deadline = time.monotonic() + timeout_s
    op: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        op = sd.get_operation(OperationId=operation_id)["Operation"]
        if op["Status"] in ("SUCCESS", "FAIL"):
            return op
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} did not reach a terminal state within {timeout_s}s (last={op})")


def _create_http_namespace(ctx, name: str) -> str:
    sd = ctx.client("servicediscovery")
    op_id = sd.create_http_namespace(Name=name)["OperationId"]
    op = _wait_operation(ctx, op_id)
    assert op["Status"] == "SUCCESS", f"namespace create failed: {op}"
    namespace_id = op["Targets"]["NAMESPACE"]

    def _cleanup():
        try:
            del_op_id = sd.delete_namespace(Id=namespace_id)["OperationId"]
            _wait_operation(ctx, del_op_id)
        except sd.exceptions.NamespaceNotFound:
            pass

    ctx.on_cleanup(_cleanup)
    return namespace_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
