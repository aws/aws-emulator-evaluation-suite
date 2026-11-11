"""dictionary-reference-tracks-referencing-feed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dictionary-reference-tracks-referencing-feed"
GROUP = "e2e"
SERVICES = ["elementalinference"]


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _error_code(fn, within_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message). A call that still
    SUCCEEDS once within_s has passed raises."""
    deadline = time.monotonic() + within_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _delete_if_present(delete, resource_id):
    """Teardown delete that tolerates a resource the check body already deleted."""
    try:
        delete(id=resource_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A feed whose subtitling output references a dictionary makes it REFERENCED and listed by that feed;
    UpdateFeed dropping the reference frees it, disassociating archives the feed, and both delete cleanly."""
    ei = ctx.client("elementalinference")
    dict_name = ctx.unique_name("sim2real-ei-dict-")
    dict_id = ei.create_dictionary(
        name=dict_name,
        language="eng",
        entries='[{"content": "birdie"}, {"content": "bogey"}]',
        tags={"Environment": "sim2real-behav"},
    )["id"]
    ctx.on_cleanup(lambda: _delete_if_present(ei.delete_dictionary, dict_id))

    feed_name = ctx.unique_name("sim2real-ei-feed-")
    output = {
        "name": "sub1",
        "outputConfig": {"subtitling": {"language": "eng", "dictionary": dict_id}},
        "status": "ENABLED",
    }
    feed_id = ei.create_feed(name=feed_name, outputs=[output], tags={"Environment": "sim2real-behav"})["id"]
    ctx.on_cleanup(lambda: _delete_if_present(ei.delete_feed, feed_id))

    got = _poll_until(
        lambda: ei.get_dictionary(id=dict_id),
        lambda r: r["status"] == "REFERENCED",
    )
    assert got["status"] == "REFERENCED", f"expected REFERENCED, got {got['status']!r}"
    assert feed_id in got.get("references", []), f"feed {feed_id} missing from references: {got.get('references')}"

    # Associate a resource: the feed transitions AVAILABLE -> ACTIVE, still carrying the dictionary reference.
    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
    active = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")
    active_dict = active["outputs"][0]["outputConfig"]["subtitling"]["dictionary"]
    assert active_dict == dict_id, f"expected output to still carry dictionary {dict_id}, got {active_dict!r}"

    # UpdateFeed (a PUT) with the dictionary field omitted drops the reference entirely.
    ei.update_feed(
        id=feed_id,
        name=feed_name,
        outputs=[{"name": "sub1", "outputConfig": {"subtitling": {"language": "eng"}}, "status": "ENABLED"}],
    )
    updated = ei.get_feed(id=feed_id)
    updated_subtitling = updated["outputs"][0]["outputConfig"]["subtitling"]
    assert "dictionary" not in updated_subtitling, f"expected dictionary field dropped, got {updated_subtitling!r}"
    freed = _poll_until(lambda: ei.get_dictionary(id=dict_id), lambda r: r["status"] == "AVAILABLE")
    assert freed.get("references", []) == [], f"expected no references after drop, got {freed.get('references')}"

    # Disassociate: the feed archives irreversibly.
    ei.disassociate_feed(id=feed_id, associatedResourceName=resource_name)
    archived = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ARCHIVED")
    assert archived["status"] == "ARCHIVED", f"expected ARCHIVED, got {archived['status']!r}"

    # Both resources can now be torn down cleanly, in either order — and each delete is proven by an
    # independent read that returns the specific not-found code, not just the mutating call's own response.
    ei.delete_feed(id=feed_id)
    feed_gone, feed_gone_message = _error_code(lambda: ei.get_feed(id=feed_id), within_s=90.0)
    assert feed_gone == "ResourceNotFoundException", f"feed {feed_id} still present after delete: {feed_gone}"
    assert feed_gone_message == "Resource not found", feed_gone_message

    ei.delete_dictionary(id=dict_id)
    dict_gone, dict_gone_message = _error_code(lambda: ei.get_dictionary(id=dict_id), within_s=90.0)
    assert dict_gone == "ResourceNotFoundException", f"dictionary {dict_id} still present after delete: {dict_gone}"
    assert dict_gone_message == "Resource not found", dict_gone_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

