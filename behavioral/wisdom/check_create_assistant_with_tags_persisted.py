"""create-assistant-with-tags-persisted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-assistant-with-tags-persisted"
GROUP = "lifecycle"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied inline on CreateAssistant (not via a separate TagResource call) are
    persisted and visible both on GetAssistant.tags and via ListTagsForResource."""
    wisdom = ctx.client("wisdom")
    name = ctx.unique_name("sim2real-behav-asst-")
    created = wisdom.create_assistant(
        name=name, type="AGENT", tags={"team": "support", "stage": "sim2real-behav"}
    )["assistant"]
    assistant_id = created["assistantId"]
    assistant_arn = created["assistantArn"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_assistant(assistantId=assistant_id)))

    expected_tags = {"team": "support", "stage": "sim2real-behav"}
    assert created["tags"] == expected_tags, f"expected {expected_tags}, got {created.get('tags')}"

    reread = wisdom.get_assistant(assistantId=assistant_id)["assistant"]
    assert reread["tags"] == expected_tags, f"expected {expected_tags}, got {reread.get('tags')}"

    via_list_tags = wisdom.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert via_list_tags == expected_tags, f"expected {expected_tags}, got {via_list_tags}"


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
