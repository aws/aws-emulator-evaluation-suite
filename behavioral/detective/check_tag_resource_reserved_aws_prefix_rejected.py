"""tag-resource-reserved-aws-prefix-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-reserved-aws-prefix-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Tag keys may not start with the reserved 'aws:' prefix; TagResource rejects such a
    key, it never becomes visible on the resource, while an ordinary key still tags fine."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    ctx.on_cleanup(lambda: _delete_graph_quietly(d, arn))

    # Tag keys with the reserved 'aws:' prefix violate the key pattern
    # '^(?!aws:)[a-zA-Z+-=._:/]+$'. botocore enforces this shape client-side
    # (ParamValidationError) before any request reaches the service -- the SDK-level
    # enforcement of the same "reserved prefix rejected" contract.
    # Empirically, a tag key with the reserved 'aws:' prefix is rejected with
    # BadRequestException (an HTTP-layer 400 raised ahead of the service's normal
    # ValidationException path), not ValidationException/ParamValidationError.
    code, message = _error(lambda: d.tag_resource(ResourceArn=arn, Tags={"aws:sim2real-reserved": "v"}))
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)", (
        f"unexpected message: {message!r}"
    )

    tags = d.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:sim2real-reserved" not in tags, f"reserved-prefixed key must never appear, got {tags!r}"

    # positive control: an ordinary (non-reserved) key tags successfully on the same resource
    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-control": "ok"})
    ctx.on_cleanup(lambda: _untag_quietly(d, arn, ["sim2real-detective-control"]))
    control_tags = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-control") == "ok",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert control_tags.get("sim2real-detective-control") == "ok", (
        f"expected the ordinary key to tag successfully, got {control_tags!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _error(fn):
    """Call fn(); return its ClientError (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _untag_quietly(d, graph_arn: str, keys: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.untag_resource(ResourceArn=graph_arn, TagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
