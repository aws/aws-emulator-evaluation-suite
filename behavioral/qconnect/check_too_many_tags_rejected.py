"""too-many-tags-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "too-many-tags-rejected"
GROUP = "overly-permissive"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a batch exceeding the 50-tag-per-resource quota; no tags are partially applied."""
    qc = ctx.client("qconnect")
    name = ctx.unique_name("sim2real-qc-asst-")
    resp = qc.create_assistant(name=name, type="AGENT")["assistant"]
    assistant_id = resp["assistantId"]
    assistant_arn = resp["assistantArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))
    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        description="assistant creation",
    )
    assert status == "ACTIVE", f"expected the prerequisite assistant to reach ACTIVE, got {status}"

    too_many_tags = {f"sim2real-tag-{i}": str(i) for i in range(51)}
    code, message = _client_error(lambda: qc.tag_resource(resourceArn=assistant_arn, tags=too_many_tags))
    assert code == "BadRequestException", (
        f"expected BadRequestException for exceeding the 50-tag quota, got {code}"
    )
    assert message == "The resultant tag set must not have more than 50 user tags.", (
        f"unexpected message {message!r}"
    )

    tags_now = qc.list_tags_for_resource(resourceArn=assistant_arn).get("tags", {})
    assert tags_now == {}, f"expected no tags to be applied from the rejected batch, found {tags_now}"

    ok_tags = {"sim2real-tag-a": "1", "sim2real-tag-b": "2"}
    qc.tag_resource(resourceArn=assistant_arn, tags=ok_tags)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.untag_resource(resourceArn=assistant_arn, tagKeys=list(ok_tags))))
    tags_after = qc.list_tags_for_resource(resourceArn=assistant_arn)["tags"]
    assert tags_after == ok_tags, f"expected a within-quota tag batch to apply, got {tags_after}"


def _client_error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises,
    so a target that accepts what AWS refuses reads as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
