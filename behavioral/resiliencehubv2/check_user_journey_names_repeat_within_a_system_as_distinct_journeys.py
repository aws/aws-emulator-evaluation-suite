"""user-journey-names-repeat-within-a-system-as-distinct-journeys."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-journey-names-repeat-within-a-system-as-distinct-journeys"
GROUP = "user-journeys"
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
    """Two user journeys with one name in one system are distinct journeys with their own ids;
    deleting one leaves the other, and the deleted one reads back not-found.
    """
    rh = ctx.client("resiliencehubv2")
    system = _create_system(ctx, rh)
    system_arn = system["systemArn"]
    first = rh.create_user_journey(systemArn=system_arn, name="checkout", description="web")["userJourney"]
    second = rh.create_user_journey(systemArn=system_arn, name="checkout", description="mobile")["userJourney"]
    assert first["userJourneyId"] != second["userJourneyId"], "each create must mint its own journey id"
    listed = {j["userJourneyId"]: j["name"] for j in rh.list_user_journeys(systemArn=system_arn)["userJourneySummaries"]}
    assert listed == {first["userJourneyId"]: "checkout", second["userJourneyId"]: "checkout"}, f"got {listed!r}"

    rh.delete_user_journey(systemArn=system_arn, userJourneyId=first["userJourneyId"])
    remaining = [j["userJourneyId"] for j in rh.list_user_journeys(systemArn=system_arn)["userJourneySummaries"]]
    assert remaining == [second["userJourneyId"]], f"expected only the second journey, got {remaining!r}"
    kept = rh.get_user_journey(systemArn=system_arn, userJourneyId=second["userJourneyId"])["userJourney"]
    assert kept["description"] == "mobile", f"the surviving journey keeps its own fields, got {kept!r}"
    code, message = _error(lambda: rh.get_user_journey(systemArn=system_arn, userJourneyId=first["userJourneyId"]))
    assert (code, message) == ("ResourceNotFoundException", f"User journey not found: {first['userJourneyId']}"), (
        f"GetUserJourney on the deleted journey: {code}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
