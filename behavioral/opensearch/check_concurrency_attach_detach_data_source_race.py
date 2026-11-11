"""concurrency-attach-detach-data-source-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrency-attach-detach-data-source-race"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent AttachDataSource calls for one domain without a clientToken, at least one succeeds (AWS
    lets both succeed) and a call that does not succeed may fail only with ConflictException; every settled record
    is ATTACHED, their count equals the distinct attachmentIds returned, and DetachDataSource removes them all.
    """
    opensearch = ctx.client("opensearch")

    domain_name = _domain_name(ctx, "appds")
    domain_resp = opensearch.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    domain_arn = domain_resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    _wait_domain_active(ctx, domain_name)

    app_name = ctx.unique_name("sim2real-app-")[:30].lower().rstrip("-")
    app = opensearch.create_application(name=app_name, tagList=[{"Key": "sim2real-check", "Value": CHECK}])
    app_id = app["id"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))

    def _attach():
        return opensearch.attach_data_source(id=app_id, dataSourceArn=domain_arn)

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_attach) for _ in range(2)]
        for fut in futures:
            try:
                outcomes.append(("ok", fut.result()))
            except Exception as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                outcomes.append(("error", code))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert successes, f"expected at least one concurrent AttachDataSource to succeed, got outcomes={outcomes}"
    for _, code in failures:
        # AWS lets both racers succeed, so there is no refusal message to pin; the code alone is graded.
        assert code == "ConflictException", (
            f"expected a losing racer to fail only with ConflictException, got {code!r} (outcomes={outcomes})"
        )

    racer_attachment_ids = {s[1]["attachmentId"] for s in successes}
    matching = _wait_matching_settled(ctx, app_id, domain_arn)
    assert all(a["status"] == "ATTACHED" for a in matching), (
        f"expected every settled attachment record to reach ATTACHED, not a corrupted "
        f"leftover state, got {matching} (outcomes={outcomes})"
    )
    assert len(matching) == len(racer_attachment_ids), (
        f"expected exactly one settled attachment record per distinct attachmentId the "
        f"racers actually got back ({racer_attachment_ids}), found {matching} (outcomes={outcomes})"
    )

    remaining = _detach_all(ctx, app_id, domain_arn, expected=len(matching))
    assert remaining == [], f"expected no orphaned attachment after detach, found {remaining}"


def _domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real{tag}").lower()
    name = "".join(ch for ch in raw if ch.isalnum() or ch == "-")[:28].rstrip("-")
    return name or f"sim2real{tag}0"


def _wait_matching_settled(
    ctx, app_id: str, domain_arn: str, timeout_s: float = 1800.0, interval_s: float = 15.0
) -> list[dict]:
    """Poll list_data_source_attachments until every record for domain_arn has left PENDING."""
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last: list[dict] = []
    while time.monotonic() < deadline:
        attachments = opensearch.list_data_source_attachments(id=app_id).get("attachments", [])
        last = [a for a in attachments if a["dataSourceArn"] == domain_arn]
        if last and all(a["status"] != "PENDING" for a in last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"attachment(s) for {domain_arn} never left PENDING within {timeout_s}s (last={last})")


def _detach_all(ctx, app_id: str, domain_arn: str, expected: int, timeout_s: float = 300.0, interval_s: float = 10.0) -> list[dict]:
    """DetachDataSource takes no attachmentId, so a race that settled into more than one
    durable record needs more than one detach call to clear all of them."""
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    remaining: list[dict] = []
    for _ in range(expected):
        try:
            opensearch.detach_data_source(id=app_id, dataSourceArn=domain_arn)
        except opensearch.exceptions.ResourceNotFoundException:
            break
        while time.monotonic() < deadline:
            attachments = opensearch.list_data_source_attachments(id=app_id).get("attachments", [])
            remaining = [a for a in attachments if a["dataSourceArn"] == domain_arn]
            if not remaining or all(a["status"] != "PENDING" for a in remaining):
                break
            time.sleep(interval_s)
        if not remaining:
            break
    return remaining


def _wait_domain_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> dict:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
