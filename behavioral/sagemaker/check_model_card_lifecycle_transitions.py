"""model-card-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-card-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModelCard moves Draft->PendingReview via UpdateModelCard and disappears after delete;
    a mutation against the deleted card is rejected too."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-modelcard-")
    content = json.dumps({"model_overview": {"model_description": "sim2real behavioral fidelity check"}})

    create_resp = sm.create_model_card(
        ModelCardName=name,
        Content=content,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    model_card_arn = create_resp["ModelCardArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_model_card(ModelCardName=name)))

    described = sm.describe_model_card(ModelCardName=name)
    assert described["ModelCardArn"] == model_card_arn
    assert described["ModelCardStatus"] == "Draft"

    sm.update_model_card(ModelCardName=name, ModelCardStatus="PendingReview")
    status = _poll_until(
        lambda: sm.describe_model_card(ModelCardName=name)["ModelCardStatus"],
        lambda s: s == "PendingReview",
        timeout_s=30,
        interval_s=2,
        description="ModelCardStatus to become PendingReview",
    )
    assert status == "PendingReview", f"expected ModelCardStatus=PendingReview, got {status}"

    sm.delete_model_card(ModelCardName=name)

    code, message = _poll_for_error(
        lambda: sm.describe_model_card(ModelCardName=name),
        timeout_s=60,
        interval_s=3,
        description="describe_model_card to report the card gone",
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_message = f"Modelcard {model_card_arn} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The delete is proven not just by an independent read but by a mutation on the
    # dead id also failing.
    update_code, update_message = _error(
        lambda: sm.update_model_card(ModelCardName=name, ModelCardStatus="Approved")
    )
    assert update_code == "ResourceNotFound", (
        f"expected ResourceNotFound updating a deleted model card, got {update_code!r}"
    )
    expected_message = f"Modelcard {model_card_arn} does not exist"
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_error(fn, *, timeout_s: float, interval_s: float, description: str = "condition"):
    """Poll fn() until it raises ClientError, returning its (code, message); a target that
    keeps succeeding past the deadline fails loudly."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s}s waiting for {description}, last value={last!r}")
        time.sleep(interval_s)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout_s}s waiting for {description}, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
