"""custom-action-concurrent-duplicate-name-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-action-concurrent-duplicate-name-single-winner"
GROUP = "concurrency"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomAction enforces a unique ActionName per account. Firing N concurrent
    creates with the SAME ActionName must let exactly one succeed; the rest are rejected
    with ConflictException, and the surviving action is exactly the one that won."""
    chatbot = ctx.client("chatbot")
    action_name = ctx.unique_name("sim2real-ca-race-")

    def _create():
        try:
            arn = chatbot.create_custom_action(
                ActionName=action_name,
                Definition={"CommandText": "echo race-winner"},
                Tags=[{"TagKey": "sim2real-race", "TagValue": action_name}],
            )["CustomActionArn"]
            return ("ok", arn)
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_create) for _ in range(8)]
        results = [f.result() for f in as_completed(futures)]

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]

    assert len(winners) == 1, f"expected exactly 1 winning create, got {len(winners)}: {results}"
    assert len(losers) == 7, f"expected exactly 7 rejected creates, got {len(losers)}: {results}"
    assert all(code == "ConflictException" for _, (code, _message) in losers), (
        f"expected every losing create to fail with ConflictException, got: {losers}"
    )

    arn = winners[0][1]
    expected_message = f"Resource with arn {arn} already exists."
    assert all(message == expected_message for _, (_code, message) in losers), (
        f"expected every losing create to name the winner {arn!r}, got: {losers}"
    )
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    got = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert got["ActionName"] == action_name, (
        f"expected the surviving action's name to be {action_name!r}, got {got['ActionName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
