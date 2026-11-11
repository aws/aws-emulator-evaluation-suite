"""untag-resource-unknown-key-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-unknown-key-fails"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource for a never-set tag key succeeds as a no-op and leaves existing tags.

    A positive control then proves UntagResource on a key that IS set removes it, so the no-op
    is not a target that ignores every UntagResource call.
    """
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-tag-"))["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=api_id)))
    resource_arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}"

    apigw.tag_resource(resourceArn=resource_arn, tags={"sim2real-env": "test"})
    tags_before = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert tags_before.get("sim2real-env") == "test"

    # No exception for a key that was never applied.
    apigw.untag_resource(resourceArn=resource_arn, tagKeys=["sim2real-never-set-key"])

    tags_after = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert tags_after.get("sim2real-env") == "test", (
        f"no-op untag of an unknown key must not disturb existing tags, got {tags_after!r}"
    )

    # positive control: UntagResource on a key that IS set must actually remove it,
    # proving the no-op above is specific to the unknown key and not a target that
    # ignores every UntagResource call.
    apigw.untag_resource(resourceArn=resource_arn, tagKeys=["sim2real-env"])
    tags_final = apigw.get_tags(resourceArn=resource_arn)["tags"]
    assert "sim2real-env" not in tags_final, (
        f"positive-control untag did not remove the key, got {tags_final!r}"
    )


def _safe(fn) -> None:
    """Teardown: done on success or NotFoundException; DeleteRestApi is rate limited account-wide,
    so retry TooManyRequestsException every 2 s for a bounded window, and raise everything else."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
