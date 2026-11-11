"""namespace-tags-at-create-round-trip-and-missing-arn."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "namespace-tags-at-create-round-trip-and-missing-arn"
GROUP = "tagging"
SERVICES = ["redshift-serverless"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Namespace tags from CreateNamespace, TagResource and UntagResource read back exactly via
    ListTagsForResource; the namespace ARN form with an id that was never minted is refused.

    Reference: https://docs.aws.amazon.com/redshift-serverless/latest/APIReference/API_ListTagsForResource.html
    """
    rss = ctx.client("redshift-serverless")

    name = ctx.unique_name("sim2real-behav-rsnstag-")
    ns = rss.create_namespace(
        namespaceName=name,
        tags=[{"key": "team", "value": "analytics"}, {"key": "env", "value": "dev"}],
    )["namespace"]
    ctx.on_cleanup(lambda: _delete_namespace(rss, name))
    arn = ns["namespaceArn"]

    got = _tags(rss, arn)
    assert got == {"team": "analytics", "env": "dev"}, f"create-time tags read back as {got!r}"

    rss.tag_resource(
        resourceArn=arn, tags=[{"key": "env", "value": "prod"}, {"key": "owner", "value": "data"}]
    )
    got = _tags(rss, arn)
    want = {"team": "analytics", "env": "prod", "owner": "data"}
    assert got == want, f"after TagResource the tags read back as {got!r}, expected {want!r}"

    rss.untag_resource(resourceArn=arn, tagKeys=["team"])
    got = _tags(rss, arn)
    want = {"env": "prod", "owner": "data"}
    assert got == want, f"after UntagResource the tags read back as {got!r}, expected {want!r}"

    missing_arn = arn[: -len(ns["namespaceId"])] + str(uuid.uuid4())
    err = _error(lambda: rss.list_tags_for_resource(resourceArn=missing_arn))
    want_err = ("ResourceNotFoundException", "Namespace not found")
    assert err == want_err, f"ListTagsForResource on a missing namespace returned {err!r}"

    err = _error(
        lambda: rss.tag_resource(resourceArn=missing_arn, tags=[{"key": "k", "value": "v"}])
    )
    assert err == want_err, f"TagResource on a missing namespace returned {err!r}"

    got = _tags(rss, arn)
    assert got == want, f"the real namespace's tags changed to {got!r} after the refused calls"


# ===== helpers =====


def _tags(rss, arn: str) -> dict:
    return {t["key"]: t["value"] for t in rss.list_tags_for_resource(resourceArn=arn)["tags"]}


def _error(fn) -> tuple:
    """(code, message) of the AWS error ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"call unexpectedly succeeded and returned {result!r}")


def _delete_namespace(rss, name: str, timeout_s: float = 300.0) -> None:
    """Delete the namespace and wait until GetNamespace reports it gone; raises at the bound."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rss.delete_namespace(namespaceName=name)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # A namespace still settling refuses the delete with a conflict; retry within the bound.
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    while time.monotonic() < deadline:
        try:
            rss.get_namespace(namespaceName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(5)
    raise AssertionError(f"namespace {name} still present {timeout_s}s after delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
