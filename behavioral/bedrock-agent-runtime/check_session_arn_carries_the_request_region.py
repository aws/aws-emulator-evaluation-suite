"""session-arn-carries-the-request-region."""
# An ARN minted by a service must name the region the request was signed for.
#
# TWO REGIONS ARE NAMED EXPLICITLY, and that is the point: a wrong-constant defect is invisible
# whenever the test value equals the constant, so a single-region run cannot distinguish "carries
# the request's region" from "always says this one region".
#
# MEASURED against the live service: CreateSession under a client signed for a region returns
# sessionArn = arn:aws:bedrock:<that region>:<account>:session/<uuid>.
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-arn-carries-the-request-region"
GROUP = "naming"
SERVICES = ["bedrock-agent-runtime"]

ALT_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An ARN minted by the service names the region the request was signed for, checked in two
    different regions so a hardcoded constant cannot satisfy both."""
    home_region = ctx.region
    assert home_region != ALT_REGION, (
        f"this check needs two distinct regions; harness region is {home_region!r} which equals the "
        f"alternate {ALT_REGION!r}. Change ALT_REGION"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]

    seen: dict[str, str] = {}
    for region in (home_region, ALT_REGION):
        br = ctx.client("bedrock-agent-runtime", region=region)
        created = br.create_session()
        session_id = created["sessionId"]
        ctx.on_cleanup(lambda b=br, s=session_id: _delete_session(b, s))

        arn = created["sessionArn"]
        parts = arn.split(":")
        assert len(parts) >= 6 and parts[0] == "arn", f"[{region}] malformed sessionArn {arn!r}"
        assert parts[2] == "bedrock", (
            f"[{region}] sessionArn must name the bedrock service, got {arn!r}"
        )
        assert parts[3] == region, (
            f"[{region}] a minted ARN must carry the region the request was signed for: expected "
            f"{region!r}, got {parts[3]!r} (full ARN {arn!r}). A target that hardcodes one region "
            f"reports the same value for both requests and fails on whichever is not that region"
        )
        assert parts[4] == account, (
            f"[{region}] the ARN must carry this account {account!r}, got {parts[4]!r} in {arn!r}"
        )
        assert parts[5].endswith(session_id), (
            f"[{region}] the ARN must identify the session it was minted for ({session_id!r}), got "
            f"{arn!r}"
        )
        seen[region] = arn

    # --- The discriminating comparison -------------------------------------------------------------
    # Each ARN was already checked against its own region; this states the relation the per-region
    # assertions imply, so a target returning one constant for both fails here with both values shown.
    assert seen[home_region] != seen[ALT_REGION], (
        f"the two regions must mint different ARNs; both read {seen[home_region]!r}"
    )
    regions_named = {arn.split(":")[3] for arn in seen.values()}
    assert regions_named == {home_region, ALT_REGION}, (
        f"the two ARNs together must name both regions; they named {sorted(regions_named)!r}. One "
        f"region appearing twice is the hardcoded-constant defect"
    )


# ===== helpers =====


def _delete_session(br, session_id: str) -> None:
    """End the session if still ACTIVE (DeleteSession refuses an ACTIVE one), then delete it.
    The client is passed in because each session lives in the region whose client created it."""
    try:
        status = br.get_session(sessionIdentifier=session_id)["sessionStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if status == "ACTIVE":
        try:
            br.end_session(sessionIdentifier=session_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    try:
        br.delete_session(sessionIdentifier=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
