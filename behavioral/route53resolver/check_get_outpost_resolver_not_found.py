"""get-outpost-resolver-not-found."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-outpost-resolver-not-found"
GROUP = "error-semantics"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOutpostResolver for a nonexistent OutpostResolverId answers HTTP 200 with no
    OutpostResolver field, not ResourceNotFoundException.
    """
    r53r = ctx.client("route53resolver")
    bogus_id = ctx.unique_name("sim2real-behav-outpost-")

    resp = r53r.get_outpost_resolver(Id=bogus_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected HTTP 200 for a nonexistent Id, got {status}"
    assert "OutpostResolver" not in resp, (
        f"expected no OutpostResolver field in the response for a nonexistent Id, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

