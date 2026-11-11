"""tags-add-list-change-remove."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-add-list-change-remove"
GROUP = 'tags'
SERVICES = ['route53']

# Public hosted zones cannot live under the RFC-2606 reserved domains, so use a
# synthetic non-reserved suffix that is never delegated.
_ZONE_SUFFIX = ".sim2real-behav-test.com."

_TRANSIENT_CODES = frozenset(
    {
        "ServiceUnavailable",
        "Throttling",
        "ThrottlingException",
        "TooManyRequestsException",
        "PriorRequestNotComplete",
        "InternalServiceError",
        "InternalFailure",
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangeTagsForResource add/remove is reflected exactly by ListTagsForResource(s), and
    requires the BARE zone id."""
    r53 = ctx.client("route53")
    zone_id, _name = _new_zone(ctx, r53, prefix="chk-tags")
    # The tagging API takes the bare id, NOT the '/hostedzone/...' path form
    # that every other Route 53 response returns.
    tag_id = _bare_id(zone_id)

    def current_tags():
        return {
            t["Key"]: t["Value"]
            for t in r53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=tag_id)[
                "ResourceTagSet"
            ]["Tags"]
        }

    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=tag_id,
        AddTags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    assert current_tags() == {"env": "test", "owner": "fidelity"}, current_tags()

    # AddTags on an existing key overwrites in place; RemoveTagKeys deletes.
    r53.change_tags_for_resource(
        ResourceType="hostedzone",
        ResourceId=tag_id,
        AddTags=[{"Key": "env", "Value": "prod"}],
        RemoveTagKeys=["owner"],
    )
    assert current_tags() == {"env": "prod"}, current_tags()

    # The batch read path must agree with the single-resource read path.
    batch = r53.list_tags_for_resources(ResourceType="hostedzone", ResourceIds=[tag_id])
    sets = {
        s["ResourceId"]: {t["Key"]: t["Value"] for t in s["Tags"]}
        for s in batch["ResourceTagSets"]
    }
    assert sets.get(tag_id) == {"env": "prod"}, sets

    # A well-formed but nonexistent zone id must be a clean not-found rather
    # than an empty tag set. (The path-form id is NOT used here: whether it
    # trips length validation or zone lookup depends on the generated zone
    # id's length, so it is not a deterministic boundary.)
    unknown_id = "Z" + uuid.uuid4().hex[:20].upper()
    err = _client_error(
        lambda: r53.list_tags_for_resource(ResourceType="hostedzone", ResourceId=unknown_id)
    )
    assert err.get("Code") == "NoSuchHostedZone", (
        f"expected NoSuchHostedZone for an unknown zone id, got {err!r}"
    )
    assert err.get("Message") == f"No hosted zone found with ID: {unknown_id}", err


def _client_error(fn) -> dict:
    """Call fn(); return the botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _caller_reference(ctx, prefix="r53") -> str:
    return ctx.unique_name(f"sim2real-behav-{prefix}-")


def _bare_id(resource_id: str) -> str:
    """Strip the '/hostedzone/' prefix from an id.

    Route 53 RETURNS ids as '/hostedzone/Z123...' but the tagging API requires the bare id:
    passing the full path fails validation with "Member must have length less than or equal
    to 32".
    """
    return resource_id.rsplit("/", 1)[-1]


def _retry_transient(fn, timeout_s=120, interval_s=2.0):
    """Retry fn() while it raises a retryable Route 53 condition."""

    def probe():
        try:
            return ("ok", fn())
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in _TRANSIENT_CODES:
                return ("retry", None)
            raise

    _status, result = _poll_until(
        probe,
        lambda r: r[0] == "ok",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description="operation to stop returning a transient Route 53 error",
    )
    return result


def _wait_for_change(r53, change_id, timeout_s=90, interval_s=2.0) -> str:
    """Poll GetChange until ChangeInfo.Status is INSYNC (or timeout)."""
    return _poll_until(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda status: status == "INSYNC",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"change {change_id} reaching INSYNC",
    )


def _empty_and_delete_zone(r53, zone_id):
    """Delete every non-apex-NS/SOA record so the zone can be deleted, then delete the zone."""
    kwargs = {"HostedZoneId": zone_id}
    try:
        while True:
            resp = r53.list_resource_record_sets(**kwargs)
            changes = [
                {"Action": "DELETE", "ResourceRecordSet": rrset}
                for rrset in resp.get("ResourceRecordSets", [])
                if rrset["Type"] not in ("NS", "SOA")
            ]
            if changes:
                try:
                    r53.change_resource_record_sets(
                        HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "HostedZoneNotFound",
                        "NoSuchHealthCheck",
                        "NoSuchHostedZone",
                    ):
                        raise
            if not resp.get("IsTruncated"):
                break
            kwargs = {
                "HostedZoneId": zone_id,
                "StartRecordName": resp["NextRecordName"],
                "StartRecordType": resp["NextRecordType"],
            }
            if resp.get("NextRecordIdentifier"):
                kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "HostedZoneNotFound",
            "NoSuchHealthCheck",
            "NoSuchHostedZone",
        ):
            raise
    try:
        r53.delete_hosted_zone(Id=zone_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchHostedZone":
            raise


def _new_zone(ctx, r53, prefix: str = "chk-rr") -> tuple[str, str]:
    name = ctx.unique_name(f"sim2real-behav-{prefix}-") + _ZONE_SUFFIX
    resp = _retry_transient(
        lambda: r53.create_hosted_zone(Name=name, CallerReference=_caller_reference(ctx))
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda: _empty_and_delete_zone(r53, zone_id))
    _wait_for_change(r53, resp["ChangeInfo"]["Id"])
    return zone_id, name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
