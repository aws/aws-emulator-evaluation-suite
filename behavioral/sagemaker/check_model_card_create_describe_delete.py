"""model-card-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-card-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ModelCard's content and status persist through describe and 404 after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-mc-")
    content = json.dumps(
        {
            "model_overview": {
                "model_description": "sim2real behavioral fidelity model card",
                "model_creator": "sim2real",
            }
        }
    )

    sm.create_model_card(ModelCardName=name, Content=content, ModelCardStatus="Draft")
    ctx.on_cleanup(lambda: _delete_mc_best_effort(sm, name))

    desc = sm.describe_model_card(ModelCardName=name)
    assert desc["ModelCardName"] == name, f"expected ModelCardName={name!r}, got {desc['ModelCardName']!r}"
    assert desc["ModelCardStatus"] == "Draft", (
        f"expected ModelCardStatus=Draft, got {desc['ModelCardStatus']!r}"
    )
    assert json.loads(desc["Content"]) == json.loads(content), (
        f"expected Content={content!r}, got {desc['Content']!r}"
    )

    sm.delete_model_card(ModelCardName=name)

    # DeleteModelCard is not read-your-writes consistent against DescribeModelCard: the read can
    # still succeed for a short window right after the delete call returns.
    code, message = _poll_for_error(
        lambda: sm.describe_model_card(ModelCardName=name),
        timeout_s=60,
        interval_s=2,
        description="DescribeModelCard 404 after DeleteModelCard",
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    expected_message = f"Modelcard {desc['ModelCardArn']} does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: sm.update_model_card(ModelCardName=name, ModelCardStatus="PendingReview")
    )
    assert update_code == "ResourceNotFound", (
        f"expected UpdateModelCard on the deleted card to fail ResourceNotFound, got {update_code!r}"
    )
    expected_message = f"Modelcard {desc['ModelCardArn']} does not exist"
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


def _delete_mc_best_effort(sm, name: str) -> None:
    try:
        sm.delete_model_card(ModelCardName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_for_error(fn, *, timeout_s, interval_s=2.0, description="condition"):
    """Poll fn() until it raises ClientError, returning its (code, message). Bounds the wait for
    eventual delete propagation without ever accepting an unconditional sleep or a silent
    last-value return; a target that never errors fails loudly instead of scoring as blocked."""
    deadline = time.monotonic() + timeout_s
    last_success = None
    while time.monotonic() < deadline:
        try:
            last_success = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not observed within {timeout_s}s; last call still SUCCEEDED and returned "
        f"{last_success!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
