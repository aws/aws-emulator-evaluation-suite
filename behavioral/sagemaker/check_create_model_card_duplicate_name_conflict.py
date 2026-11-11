"""create-model-card-duplicate-name-conflict."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-card-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateModelCard calls with one name leave exactly one success and one
    ConflictException, and the card is described with the winner's ARN, status Draft and the
    winner's content."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-card-dup-")
    content = json.dumps({"model_overview": {"model_description": "sim2real concurrency check"}})

    def _create():
        try:
            resp = sm.create_model_card(
                ModelCardName=name,
                Content=content,
                ModelCardStatus="Draft",
                Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
            )
            return ("ok", resp["ModelCardArn"])
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _create(), range(2)))
    ctx.on_cleanup(lambda: _safe_delete(sm, name))

    outcomes = [r[0] for r in results]
    assert outcomes.count("ok") == 1, f"expected exactly one success, got {results}"
    assert outcomes.count("err") == 1, f"expected exactly one failure, got {results}"

    winner_arn = next(v for (o, v) in results if o == "ok")
    err_code, err_message = next(v for (o, v) in results if o == "err")
    assert err_code == "ConflictException", f"expected ConflictException, got {err_code}"
    expected = f"Modelcard {winner_arn} with version 1 already exists"
    assert err_message == expected, f"expected message {expected!r}, got {err_message!r}"

    described = sm.describe_model_card(ModelCardName=name)
    assert described["ModelCardName"] == name
    assert described["ModelCardArn"] == winner_arn, (
        f"independent read's arn {described['ModelCardArn']!r} does not match the "
        f"racer that reported success {winner_arn!r}"
    )
    assert described["ModelCardStatus"] == "Draft", (
        f"expected Draft, got {described['ModelCardStatus']!r}"
    )
    assert json.loads(described["Content"]) == json.loads(content), (
        f"expected the winning racer's content to survive the race untouched, "
        f"got {described['Content']!r}"
    )


def _safe_delete(sm, name):
    try:
        sm.delete_model_card(ModelCardName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
