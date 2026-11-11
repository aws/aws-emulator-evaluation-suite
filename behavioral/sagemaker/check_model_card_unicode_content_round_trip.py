"""model-card-unicode-content-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-card-unicode-content-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModelCard JSON Content containing unicode characters and nested numeric
    fields is returned byte-identical by DescribeModelCard (no re-encoding,
    rounding, or mangling of the stored string)."""
    sm = ctx.client("sagemaker")

    content = {
        "model_overview": {
            "model_description": "caf\u00e9 \u2603\ufe0f \u4e2d\u6587\u6a21\u578b \U0001F600 \u00e9\u00e8\u00ea",
            "model_creator": "\u00e9quipe-\u00e9toile",
            "problem_type": "BinaryClassification",
        },
        "evaluation_details": [
            {
                "name": "eval-unicode-\u00fc",
                "evaluation_observation": "\u2713 pass\u00e9 \u2014 91.35% \u00b1 0.02",
                "metric_groups": [
                    {
                        "name": "metrics",
                        "metric_data": [
                            {"name": "accuracy", "type": "number", "value": 0.913547028199},
                            {"name": "count", "type": "number", "value": 12345},
                        ],
                    }
                ],
            }
        ],
    }
    content_str = json.dumps(content, ensure_ascii=False)

    model_card_name = ctx.unique_name("sim2real-modelcard-")
    sm.create_model_card(
        ModelCardName=model_card_name,
        Content=content_str,
        ModelCardStatus="Draft",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_model_card(sm, model_card_name))

    described = sm.describe_model_card(ModelCardName=model_card_name)
    returned_str = described["Content"]

    assert returned_str == content_str, "Content string was not returned byte-identical"

    parsed = json.loads(returned_str)
    assert parsed["model_overview"]["model_description"] == content["model_overview"]["model_description"], (
        "model_description unicode text was mangled on round-trip"
    )
    assert parsed["model_overview"]["model_creator"] == content["model_overview"]["model_creator"], (
        "model_creator unicode text was mangled on round-trip"
    )
    metric_data = parsed["evaluation_details"][0]["metric_groups"][0]["metric_data"]
    assert metric_data[0]["value"] == 0.913547028199, "high-precision float was rounded/truncated"
    assert metric_data[1]["value"] == 12345, "integer-valued metric was mangled"

    sm.delete_model_card(ModelCardName=model_card_name)
    # DeleteModelCard is async: DescribeModelCard keeps returning 200 with
    # ModelCardProcessingStatus="DeletePending" for a window before it 404s.
    not_found_code, not_found_message, last_body = _poll_deleted(
        sm, model_card_name, timeout_s=60, interval_s=2
    )
    assert not_found_code == "ResourceNotFound", (
        f"a deleted model card must eventually be reported not-found within 60s, "
        f"got code={not_found_code!r} last_body={last_body!r}"
    )
    expected_message = f"Modelcard {described['ModelCardArn']} does not exist"
    assert not_found_message == expected_message, (
        f"expected message {expected_message!r}, got {not_found_message!r}"
    )


def _delete_model_card(sm, model_card_name):
    try:
        sm.delete_model_card(ModelCardName=model_card_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_deleted(sm, model_card_name, *, timeout_s, interval_s):
    import time

    deadline = time.monotonic() + timeout_s
    code = None
    message = None
    body = None
    while time.monotonic() < deadline:
        try:
            body = sm.describe_model_card(ModelCardName=model_card_name)
            code = None
            message = None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
            body = None
        if code == "ResourceNotFound":
            return code, message, body
        time.sleep(interval_s)
    return code, message, body


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
