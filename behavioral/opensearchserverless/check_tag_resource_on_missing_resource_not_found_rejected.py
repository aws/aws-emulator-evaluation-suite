"""tag-resource-on-missing-resource-not-found-rejected."""
from __future__ import annotations

import re
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-on-missing-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against the ARN of a collection group that was already deleted returns
    ResourceNotFoundException, while tagging a still-existing collection group succeeds
    (positive control) in the same run."""
    aoss = ctx.client("opensearchserverless")

    deleted_name = _short_name(ctx, "sim2real-tagdel")
    deleted = aoss.create_collection_group(name=deleted_name, standbyReplicas="DISABLED")[
        "createCollectionGroupDetail"
    ]
    deleted_arn = deleted["arn"]
    aoss.delete_collection_group(id=deleted["id"])

    live_name = _short_name(ctx, "sim2real-taglive")
    live = aoss.create_collection_group(name=live_name, standbyReplicas="DISABLED")[
        "createCollectionGroupDetail"
    ]
    live_arn = live["arn"]

    def _cleanup() -> None:
        try:
            aoss.delete_collection_group(id=live["id"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    # negative: tagging the deleted resource's ARN is rejected
    code, message = _error(
        lambda: aoss.tag_resource(resourceArn=deleted_arn, tags=[{"key": "sim2real", "value": "x"}])
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Collection Group ID {deleted['id']} is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: tagging a still-existing collection group of the same kind succeeds
    aoss.tag_resource(resourceArn=live_arn, tags=[{"key": "sim2real", "value": "x"}])
    tags_now = aoss.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert {"key": "sim2real", "value": "x"} in tags_now


def _short_name(ctx: Any, prefix: str) -> str:
    raw = ctx.unique_name(prefix + "-").lower()
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not raw or not raw[0].isalpha():
        raw = "a" + raw
    raw = raw[:32].rstrip("-")
    while len(raw) < 3:
        raw += "0"
    return raw


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
