"""duplicate-model-card-creation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-model-card-creation-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing ModelCard name is rejected with ConflictException."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-mc-dup-")
    original_content = json.dumps(
        {"model_overview": {"model_description": "original sim2real model card"}}
    )

    tags_kv = [{"Key": "sim2real", "Value": CHECK}]
    sm.create_model_card(
        ModelCardName=name,
        Content=original_content,
        ModelCardStatus="Draft",
        Tags=tags_kv,
    )
    ctx.on_cleanup(lambda: _delete_mc_best_effort(sm, name))

    conflicting_content = json.dumps(
        {"model_overview": {"model_description": "a completely different model card"}}
    )
    code, message = _error(
        lambda: sm.create_model_card(
            ModelCardName=name, Content=conflicting_content, ModelCardStatus="Draft"
        )
    )
    assert code == "ConflictException", (
        f"re-creating an existing ModelCardName must be refused with ConflictException; got {code!r}"
    )
    expected = (
        f"Modelcard arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-card/{name} "
        f"with version 1 already exists"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The effect must be absent: the original content must be untouched by the rejected call.
    desc = sm.describe_model_card(ModelCardName=name)
    assert json.loads(desc["Content"]) == json.loads(original_content), (
        f"the rejected duplicate create must not modify the existing card's content; expected "
        f"{original_content!r}, describe returned {desc['Content']!r}"
    )

    # Positive control in the same file: describing the (unmodified) card still works.
    assert desc["ModelCardName"] == name, (
        f"describe_model_card must return the name it was asked for; expected {name!r}, got "
        f"{desc['ModelCardName']!r}"
    )
    assert desc["ModelCardStatus"] == "Draft", (
        f"the untouched card must still report its original Draft status; got "
        f"{desc['ModelCardStatus']!r}"
    )

    # --- restore: freeing the name must make the identical call that was just rejected succeed.
    # The retry is a bounded poll, not a single shot: SageMaker's delete need not be instantly
    # consistent for name reuse, so a ConflictException immediately after delete is retried; any
    # other error is a real defect and must not be swallowed.
    sm.delete_model_card(ModelCardName=name)
    deadline = time.monotonic() + 30
    resp = None
    last_code = None
    while resp is None and time.monotonic() < deadline:
        try:
            resp = sm.create_model_card(
                ModelCardName=name,
                Content=conflicting_content,
                ModelCardStatus="Draft",
                Tags=tags_kv,
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "ConflictException":
                raise
            time.sleep(2)
    assert resp is not None, (
        f"the identical create call must succeed once the name is free; it never did within 30s "
        f"of deleting the original, last saw {last_code!r}"
    )
    assert resp["ModelCardArn"], f"create_model_card on the freed name returned no ARN: {resp!r}"

    restored = sm.describe_model_card(ModelCardName=name)
    assert json.loads(restored["Content"]) == json.loads(conflicting_content), (
        f"the retried create is the one that must land now the conflict is gone; expected "
        f"{conflicting_content!r}, describe returned {restored['Content']!r}"
    )


def _delete_mc_best_effort(sm, name: str) -> None:
    try:
        sm.delete_model_card(ModelCardName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"expected ConflictException on the duplicate create, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
