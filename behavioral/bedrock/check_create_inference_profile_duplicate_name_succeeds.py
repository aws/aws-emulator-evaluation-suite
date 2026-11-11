"""create-inference-profile-duplicate-name-succeeds."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-inference-profile-duplicate-name-succeeds"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInferenceProfile rejects an unknown foundation-model source; duplicate
    inferenceProfileName across profiles is NOT restricted (empirically verified: real
    AWS returns 201 both times with distinct ARNs, not ConflictException)."""
    bedrock = ctx.client("bedrock")
    source_arn = _a_system_defined_profile_arn_or_skip(bedrock)
    name = ctx.unique_name("sim2real-infprofile-dup-")

    # overly-permissive boundary: an unknown/malformed source foundation model must be
    # rejected, not silently accepted.
    bogus_source_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/sim2real-does-not-exist-v1"
    bad_code, bad_message = _error_code(
        lambda: bedrock.create_inference_profile(
            inferenceProfileName=ctx.unique_name("sim2real-infprofile-bad-"),
            modelSource={"copyFrom": bogus_source_arn},
        )
    )
    assert bad_code == "ValidationException", (
        f"code={bad_code!r}"
    )
    assert bad_message == "The provided ARN is invalid.", (
        f"expected the exact ValidationException message AWS returns, got {bad_message!r}"
    )

    profile_tags = [{"key": "purpose", "value": "sim2real-behavioral-check"}]

    first = bedrock.create_inference_profile(
        inferenceProfileName=name, modelSource={"copyFrom": source_arn}, tags=profile_tags
    )
    first_arn = first["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _safe_delete_profile(bedrock, first_arn))
    assert first["status"] == "ACTIVE"

    # empirical fact (not a validation boundary): a second CreateInferenceProfile with the
    # *same* inferenceProfileName succeeds and produces a distinct ARN -- names are not
    # unique identifiers for this resource.
    second = bedrock.create_inference_profile(
        inferenceProfileName=name, modelSource={"copyFrom": source_arn}, tags=profile_tags
    )
    second_arn = second["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _safe_delete_profile(bedrock, second_arn))
    assert second["status"] == "ACTIVE"
    assert second_arn != first_arn

    matches = _poll_until(
        lambda: [
            s
            for s in _list_all_profiles(bedrock, type_equals="APPLICATION")
            if s["inferenceProfileName"] == name
        ],
        lambda ms: len(ms) >= 2,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert len(matches) == 2
    assert {m["inferenceProfileArn"] for m in matches} == {first_arn, second_arn}


def _a_system_defined_profile_arn_or_skip(bedrock) -> str:
    """An Amazon Nova Micro system-defined profile, else the first one listed.

    Copying a profile is refused with AccessDeniedException until the account is granted its
    model (a third-party model, Nova Premier), so the source is a model every account may use.
    """
    summaries = _list_all_profiles(bedrock, type_equals="SYSTEM_DEFINED")
    if not summaries:
        raise AssertionError(
            "no system-defined (cross-Region) inference profile visible via "
            "ListInferenceProfiles in this account/region to copy from"
        )
    micro = [s for s in summaries if ".amazon.nova-micro-" in s["inferenceProfileId"]]
    return (micro or summaries)[0]["inferenceProfileArn"]


def _list_all_profiles(bedrock, type_equals=None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {}
    if type_equals:
        kwargs["typeEquals"] = type_equals
    while True:
        resp = bedrock.list_inference_profiles(**kwargs)
        out.extend(resp.get("inferenceProfileSummaries", []))
        token = resp.get("nextToken")
        if not token:
            return out
        kwargs["nextToken"] = token


def _safe_delete_profile(bedrock, profile_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


