"""delete-system-removes-its-user-journeys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-system-removes-its-user-journeys"
GROUP = "system-association"
SERVICES = ["resiliencehubv2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_system(ctx, rh, **kwargs) -> dict:
    """A system deleted at teardown."""
    system = rh.create_system(name=ctx.unique_name("sim2real-behav-rhv2-sys-"), **kwargs)["system"]
    arn = system["systemArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_system(systemArn=arn), "ResourceNotFoundException"))
    return system


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteSystem on a system that still holds user journeys succeeds, and the journeys become
    unreachable through the deleted system.
    """
    rh = ctx.client("resiliencehubv2")
    system = _create_system(ctx, rh)
    system_arn, system_id = system["systemArn"], system["systemId"]
    ids = {rh.create_user_journey(systemArn=system_arn, name=n)["userJourney"]["userJourneyId"]
           for n in ("browse", "checkout", "returns")}
    listed = {j["userJourneyId"] for page in rh.get_paginator("list_user_journeys").paginate(systemArn=system_arn)
              for j in page["userJourneySummaries"]}
    assert listed == ids, f"expected the three journeys, got {len(listed)}"

    rh.delete_system(systemArn=system_arn)
    gone = f"System not found: {system_id}"
    code, message = _error(lambda: rh.list_user_journeys(systemArn=system_arn))
    assert (code, message) == ("ResourceNotFoundException", gone), f"ListUserJourneys: {code}: {message!r}"
    some = sorted(ids)[0]
    code, message = _error(lambda: rh.get_user_journey(systemArn=system_arn, userJourneyId=some))
    assert (code, message) == ("ResourceNotFoundException", gone), f"GetUserJourney: {code}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
