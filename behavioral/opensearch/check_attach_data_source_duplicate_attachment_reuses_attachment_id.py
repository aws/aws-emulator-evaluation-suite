"""attach-data-source-duplicate-attachment-reuses-attachment-id."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "attach-data-source-duplicate-attachment-reuses-attachment-id"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Attaching the same dataSourceArn to an application twice is idempotent: it succeeds with the
    same attachmentId and no duplicate record; attaching another source leaves it intact.
    """
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)
    arn = _bogus_domain_arn(ctx, "sim2real-attach-dup")

    first = aos.attach_data_source(id=app_id, dataSourceArn=arn)
    ctx.on_cleanup(lambda: _safe(lambda: aos.detach_data_source(id=app_id, dataSourceArn=arn)))
    assert first["dataSourceArn"] == arn, "positive-control first attach did not accept the source"
    first_attachment_id = first["attachmentId"]
    assert first_attachment_id, f"attach_data_source response carried no attachmentId: {first}"

    # Second call with the identical (id, dataSourceArn) pair: the real service is
    # idempotent here rather than raising ConflictException.
    second = aos.attach_data_source(id=app_id, dataSourceArn=arn)
    assert second["dataSourceArn"] == arn, f"unexpected response on repeat attach: {second}"
    assert second["attachmentId"] == first_attachment_id, (
        f"repeat attach returned a different attachmentId ({second['attachmentId']!r}) "
        f"than the original ({first_attachment_id!r}), implying a duplicate record was created"
    )

    listing = _list_attachments(aos, app_id)
    matching = [a for a in listing if a["dataSourceArn"] == arn]
    assert len(matching) == 1, f"repeat attach call created more than one attachment record: {matching}"

    # Attaching a different source must not disturb the original attachment.
    unrelated_arn = _bogus_domain_arn(ctx, "sim2real-attach-dup-other")
    aos.attach_data_source(id=app_id, dataSourceArn=unrelated_arn)
    ctx.on_cleanup(lambda: _safe(lambda: aos.detach_data_source(id=app_id, dataSourceArn=unrelated_arn)))
    listing_after = _list_attachments(aos, app_id)
    matching_after = [a for a in listing_after if a["dataSourceArn"] == arn]
    assert len(matching_after) == 1, f"unrelated attach disturbed the original attachment: {matching_after}"




def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"] + "::" + err.response["Error"].get("Message", "")
    return None


def _safe(fn) -> None:
    """Teardown call: a gone resource is done, a busy application is retried every 2 s."""
    from botocore.exceptions import ClientError

    # Three teardowns share the suite's 1800 s cleanup budget, minus a margin.
    deadline = time.monotonic() + 580.0
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ResourceNotFoundException":
                return
            # Only the transitional CREATING state is retried; a FAILED application raises at once.
            busy = code == "ConflictException" or (
                code == "ValidationException"
                and "is in CREATING state" in message
                and "Cannot detach data source" in message
            )
            if not busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real-check", "Value": CHECK}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_application(id=app_id)))
    return app_id


def _bogus_domain_arn(ctx, prefix: str) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return f"arn:aws:es:{ctx.region}:{account_id}:domain/{cleaned[:28]}"


def _list_attachments(aos, app_id: str) -> list:
    out: list = []
    next_token = None
    while True:
        kwargs = {"id": app_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = aos.list_data_source_attachments(**kwargs)
        out.extend(resp.get("attachments", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
