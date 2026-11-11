"""create-stream-group-client-token-idempotent."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-group-client-token-idempotent"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing the same ClientToken with identical CreateStreamGroup parameters returns the
    same resource instead of creating a second one (idempotency window)."""
    gls = ctx.client("gameliftstreams")
    token = uuid.uuid4().hex
    description = ctx.unique_name("sim2real-behav-gls-sg-")

    try:
        first = gls.create_stream_group(
            Description=description,
            StreamClass="gen6n_small",
            ClientToken=token,
            Tags={"sim2real-env": "test"},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=first["Arn"])))

    second = gls.create_stream_group(
        Description=description,
        StreamClass="gen6n_small",
        ClientToken=token,
        Tags={"sim2real-env": "test"},
    )
    assert second["Arn"] == first["Arn"]
    assert second["Id"] == first["Id"]

    all_groups = _list_all_stream_groups(gls)
    matching = [g for g in all_groups if g.get("Id") == first["Id"]]
    assert len(matching) == 1


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_stream_groups(gls):
    items = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = gls.list_stream_groups(**kwargs)
        items.extend(page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
