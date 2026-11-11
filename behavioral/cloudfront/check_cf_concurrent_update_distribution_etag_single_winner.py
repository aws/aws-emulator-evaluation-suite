"""cf-concurrent-update-distribution-etag-single-winner."""
from __future__ import annotations

import copy
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "cf-concurrent-update-distribution-etag-single-winner"
GROUP = 'concurrency'
SERVICES = ['cloudfront']

_RACERS = 8


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each typically take a few minutes; 900 s leaves a
    wide margin.
    """
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete.

    DeleteDistribution issued immediately after the disabling UpdateDistribution is
    refused with ``DistributionNotDisabled``, so the Deployed wait is mandatory rather than
    defensive — and it is required even for a distribution that was NEVER enabled, because a
    freshly created one is InProgress. A distribution left behind cannot be found
    by name later, because its id is server-minted.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """Eight concurrent UpdateDistribution calls sharing one ETag: exactly one wins, the seven others
    are refused PreconditionFailed, and the persisted config is one racer's value in full.
    """
    cf = ctx.client("cloudfront")

    base_cfg = {
        "CallerReference": ctx.unique_name("sim2real-behav-cfrace-cr-"),
        "Comment": "sim2real etag race baseline",
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "custom-origin",
            "DomainName": "example.com",
            "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                   "OriginProtocolPolicy": "https-only"},
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "custom-origin",
            "ViewerProtocolPolicy": "allow-all",
            # Managed CachingDisabled — the distribution never serves; this only satisfies the API.
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    dist_id = cf.create_distribution(DistributionConfig=base_cfg)["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))

    # ONE read, ONE ETag: this is the version token all eight racers compare-and-swap against.
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    shared_etag = cfg_resp["ETag"]
    live_cfg = cfg_resp["DistributionConfig"]
    comments = [f"sim2real racer {i}" for i in range(_RACERS)]

    def race(comment: str) -> tuple[str, bool, str, str]:
        cfg = copy.deepcopy(live_cfg)
        cfg["Comment"] = comment
        try:
            cf.update_distribution(Id=dist_id, IfMatch=shared_etag, DistributionConfig=cfg)
            return comment, True, "", ""
        except Exception as exc:  # noqa: BLE001 — the error CODE is the observation
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            # Never a falsy sentinel: an exception with no recoverable code must not read as a
            # missing code, which would be indistinguishable from a clean rejection.
            message = getattr(exc, "response", {}).get("Error", {}).get("Message")
            return comment, False, code or f"<no Error.Code: {type(exc).__name__}: {exc}>", message

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(race, comments))

    winners = [c for c, ok, _, _ in results if ok]
    loser_codes = sorted({code for _, ok, code, _ in results if not ok})
    loser_messages = sorted({message for _, ok, _, message in results if not ok})

    assert len(winners) == 1, (
        f"expected exactly one of {_RACERS} same-ETag updates to succeed, {len(winners)} did: "
        f"{winners!r} (loser codes: {loser_codes!r})"
    )
    assert loser_codes == ["PreconditionFailed"], (
        f"the losing racers reported {loser_codes!r} instead of PreconditionFailed only"
    )
    assert loser_messages == [
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    ], f"PreconditionFailed messages of the losing racers: {loser_messages!r}"

    final_comment = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["Comment"]
    assert final_comment in comments, (
        f"the stored comment is not any racer's value: {final_comment!r} (racers: {comments!r})"
    )
    assert final_comment == winners[0], (
        f"the persisted config disagrees with the racer that was told it won: "
        f"{final_comment!r} vs {winners[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
