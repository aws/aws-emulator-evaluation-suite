"""assistant-create-active-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assistant-create-active-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssistant transitions to ACTIVE and DeleteAssistant removes it: GetAssistant 404s,
    and a mutation against the dead id (TagResource) is rejected too, not just a read."""
    qc = ctx.client("qconnect")
    name = ctx.unique_name("sim2real-qc-asst-")
    created = qc.create_assistant(name=name, type="AGENT", tags={"sim2real-check": CHECK})["assistant"]
    assistant_id = created["assistantId"]
    assistant_arn = created["assistantArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_assistant(assistantId=assistant_id)))

    status = _poll_until(
        lambda: qc.get_assistant(assistantId=assistant_id)["assistant"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"assistant did not reach ACTIVE, got {status}"

    qc.delete_assistant(assistantId=assistant_id)

    def _get_code():
        try:
            qc.get_assistant(assistantId=assistant_id)
            return None
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")

    code = _poll_until(_get_code, lambda c: c is not None, timeout_s=60.0)
    assert code == ("ResourceNotFoundException", "Assistant does not exist."), f"expected ResourceNotFoundException, got {code}"

    def _tag_dead_assistant():
        try:
            result = qc.tag_resource(resourceArn=assistant_arn, tags={"probe": "post-delete"})
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected TagResource on a deleted assistant to fail, got {result!r}")

    tag_code = _tag_dead_assistant()
    assert tag_code == ("NotFoundException", "Resource was not found"), (
        f"expected TagResource on the deleted assistant to fail with NotFoundException, got {tag_code}"
    )


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
