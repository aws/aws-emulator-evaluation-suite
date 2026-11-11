"""concurrent-tag-resource-different-keys-no-lost-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-tag-resource-different-keys-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """10 concurrent TagResource calls on one custom action, each adding a different key (retrying
    ConflictException "Unable to modify resource Tags. Please try again."), leave all 10 tags in
    ListTagsForResource: TagResource merges, with no lost update."""
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realtagrace").replace("-", "")[:64]
    arn = chatbot.create_custom_action(ActionName=name, Definition={"CommandText": "echo tagrace"})[
        "CustomActionArn"
    ]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn))

    workers = 10

    def _tag(i: int):
        from botocore.exceptions import ClientError
        import time

        deadline = time.monotonic() + 20.0
        while True:
            try:
                chatbot.tag_resource(ResourceARN=arn, Tags=[{"TagKey": f"race-{i}", "TagValue": str(i)}])
                return i
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() > deadline:
                    raise
                time.sleep(0.3)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_tag, i) for i in range(workers)]
        for f in as_completed(futures):
            f.result()  # surface any non-retryable exception

    tags = chatbot.list_tags_for_resource(ResourceARN=arn)["Tags"]
    tag_map = {t["TagKey"]: t["TagValue"] for t in tags}
    for i in range(workers):
        assert tag_map.get(f"race-{i}") == str(i), f"tag race-{i} was lost under concurrent TagResource calls"


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
