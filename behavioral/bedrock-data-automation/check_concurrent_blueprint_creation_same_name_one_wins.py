"""concurrent-blueprint-creation-same-name-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-blueprint-creation-same-name-one-wins"
GROUP = "concurrency"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = (
    '{"class": "Race", "description": "concurrency schema", '
    '"properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}}}'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateBlueprint calls with the SAME blueprintName: exactly one succeeds,
    the rest fail with ConflictException (name conflict / concurrent create race)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-race")
    racers = 6

    def _attempt(_i):
        try:
            resp = bda.create_blueprint(
                blueprintName=name,
                type="DOCUMENT",
                schema=_SCHEMA,
                tags=[{"key": "purpose", "value": "sim2real-race"}],
            )
            return ("ok", resp["blueprint"]["blueprintArn"])
        except Exception as err:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))
            raise

    with ThreadPoolExecutor(max_workers=racers) as pool:
        results = list(pool.map(_attempt, range(racers)))

    successes = [arn for kind, arn in results if kind == "ok"]
    failures = [code for kind, code in results if kind == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racers - 1, f"expected {racers - 1} losers, got {len(failures)}: {results}"
    assert all(code == "ConflictException" for code, _ in failures), failures
    assert all(message == "Blueprint name already exists." for _, message in failures), failures

    winner_arn = successes[0]

    def _cleanup_winner():
        from botocore.exceptions import ClientError

        try:
            bda.delete_blueprint(blueprintArn=winner_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_winner)

    fetched = bda.get_blueprint(blueprintArn=winner_arn)["blueprint"]
    assert fetched["blueprintName"] == name

    # The delete is a free negative: an operation that just worked (GetBlueprint) must now fail
    # with the specific not-found code once the winner is torn down.
    bda.delete_blueprint(blueprintArn=winner_arn)
    from botocore.exceptions import ClientError

    try:
        bda.get_blueprint(blueprintArn=winner_arn)
        raise AssertionError(f"expected ResourceNotFoundException after delete, got success for {winner_arn}")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert message == "Blueprint Arn not found.", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
