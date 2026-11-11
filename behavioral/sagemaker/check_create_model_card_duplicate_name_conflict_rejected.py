"""create-model-card-duplicate-name-conflict-rejected."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-model-card-duplicate-name-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateModelCard calls with the same ModelCardName resolve to exactly
    one winner; the loser gets ConflictException. This is a distinct name-collision axis
    from the CreateExperiment name conflict covered elsewhere."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-mc-")
    content = json.dumps({"model_overview": {"model_creator": "sim2real-behavioral-check"}})

    def _create():
        return sm.create_model_card(
            ModelCardName=name,
            Content=content,
            ModelCardStatus="Draft",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_create) for _ in range(2)]
        results = []
        for fut in futures:
            try:
                results.append(("ok", fut.result()))
            except Exception as exc:  # noqa: BLE001 - classify below
                results.append(("error", exc))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)} (results={results!r})"
    assert len(errors) == 1, f"expected exactly 1 loser, got {len(errors)}"

    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=name))

    code, message = _client_error_code_and_message(errors[0])
    assert code == "ConflictException", f"expected ConflictException for the losing racer, got {code!r}"
    expected_message = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{name} "
        f"with version 1 already exists"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = sm.describe_model_card(ModelCardName=name)
    assert described["ModelCardName"] == name, (
        f"expected the winning card {name!r} to be independently readable, got {described!r}"
    )


def _client_error_code_and_message(exc):
    """Return a ClientError's (code, message); any other exception is a failure of its own,
    never a falsy code."""
    from botocore.exceptions import ClientError

    if not isinstance(exc, ClientError):
        raise AssertionError(f"expected the losing racer to get a ClientError, got {exc!r}")
    err = exc.response["Error"]
    return err["Code"], err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
