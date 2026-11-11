"""oai-concurrent-update-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oai-concurrent-update-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers update the same OAI with the same stale ETag: exactly one wins, the rest are rejected."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-race-")

    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "sim2real-behav initial"}
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    shared_stale_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            etag = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
        except cf.exceptions.NoSuchCloudFrontOriginAccessIdentity:
            return
        cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    n_racers = 6

    def _racer(i: int) -> str:
        try:
            cf.update_cloud_front_origin_access_identity(
                Id=oai_id,
                IfMatch=shared_stale_etag,
                CloudFrontOriginAccessIdentityConfig={
                    "CallerReference": caller_ref,
                    "Comment": f"sim2real-behav racer-{i}",
                },
            )
            return "ok"
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code", "Unknown")

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        outcomes = list(pool.map(_racer, range(n_racers)))

    ok_count = sum(1 for o in outcomes if o == "ok")
    precondition_failed_count = sum(1 for o in outcomes if o == "PreconditionFailed")

    assert ok_count == 1, f"exactly one racer must win the optimistic-concurrency update, got {ok_count}: {outcomes}"
    assert precondition_failed_count == n_racers - 1, (
        f"the remaining {n_racers - 1} racers must all fail with PreconditionFailed, got: {outcomes}"
    )

    # Independent read at the destination: the persisted state must match the racer whose
    # own call reported success, not merely agree that "some" call succeeded.
    winner_i = outcomes.index("ok")
    final = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    final_etag = final["ETag"]
    final_comment = final["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"]

    assert final_etag != shared_stale_etag, (
        f"the OAI's ETag must have advanced past the value the racers raced on, still {final_etag!r}"
    )
    expected_comment = f"sim2real-behav racer-{winner_i}"
    assert final_comment == expected_comment, (
        f"persisted Comment must match the racer that reported success, got {final_comment!r} expected {expected_comment!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
