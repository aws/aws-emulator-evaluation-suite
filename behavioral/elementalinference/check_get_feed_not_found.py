"""get-feed-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-feed-not-found"
GROUP = "errors"
SERVICES = ["elementalinference"]


def _error_code(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFeed on a real feed succeeds (positive control), and GetFeed on a syntactically valid
    but nonexistent 19-char lowercase-alnum id returns ResourceNotFoundException."""
    ei = ctx.client("elementalinference")

    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name,
        outputs=[_subtitling_output("sub1")],
        tags={"Environment": "sim2real-behav"},
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    real = ei.get_feed(id=feed_id)
    assert real["id"] == feed_id, f"expected {feed_id}, got {real.get('id')}"

    bogus_id = "zzzzzzzzzzzzzzzzzzz"  # 19 chars, matches ^[a-z0-9]{19}$, never allocated
    code, message = _error_code(lambda: ei.get_feed(id=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Resource not found", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
