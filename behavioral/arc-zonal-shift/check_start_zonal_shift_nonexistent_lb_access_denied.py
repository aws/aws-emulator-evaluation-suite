"""start-zonal-shift-nonexistent-lb-access-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-zonal-shift-nonexistent-lb-access-denied"
GROUP = "overly-permissive"
SERVICES = ["arc-zonal-shift"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartZonalShift on a well-formed same-account ARN of a load balancer that was never created fails
    AccessDeniedException, not ResourceNotFoundException, so ARN existence is not disclosed."""
    arc = ctx.client("arc-zonal-shift")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"loadbalancer/net/{ctx.unique_name('sim2real-arczs-')}/0123456789abcdef"
    )

    code, message = _error_detail(
        lambda: arc.start_zonal_shift(
            resourceIdentifier=fake_arn,
            awayFrom="use1-az1",
            expiresIn="1h",
            comment="sim2real-not-found-probe",
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got CODE={code!r}"
    assert message == "Requested resource is not available.", (
        f"expected message 'Requested resource is not available.', got {message!r}"
    )

    # Positive control: the API is otherwise healthy -- an unrelated, well-formed call succeeds.
    resp = arc.list_zonal_shifts()
    assert "items" in resp, f"list_zonal_shifts returned no 'items' key: {resp!r}"


def _error_detail(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
