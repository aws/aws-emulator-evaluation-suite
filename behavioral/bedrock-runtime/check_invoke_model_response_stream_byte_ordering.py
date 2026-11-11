"""invoke-model-response-stream-byte-ordering."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "invoke-model-response-stream-byte-ordering"
GROUP = "ordering"
SERVICES = ["bedrock-runtime"]

# amazon.titan-text-express-v1 is end of life: InvokeModelWithResponseStream against it fails
# with ResourceNotFoundException. The stream ordering is graded on the live model.
_EOL_MODEL_ID = "amazon.titan-text-express-v1"
_LIVE_MODEL_ID = "amazon.nova-lite-v1:0"


@tags(
    "axis:rejection",
    "cap:c5",
    "cap:c6",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A live model's InvokeModelWithResponseStream events arrive in order (messageStart, text
    deltas, contentBlockStop, messageStop), and the end-of-life titan-text-express-v1 is refused
    with ResourceNotFoundException naming end of life by InvokeModel* and GetFoundationModel alike.
    """
    brt = ctx.client("bedrock-runtime")
    bedrock = ctx.client("bedrock")

    # Positive control: the response-stream transport is healthy end to end on a live model.
    live_resp = brt.invoke_model_with_response_stream(
        modelId=_LIVE_MODEL_ID,
        body=json.dumps(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": "Reply with exactly the word PONG and nothing else."}],
                    }
                ],
                "inferenceConfig": {"maxTokens": 20, "temperature": 0},
            }
        ),
        contentType="application/json",
        accept="application/json",
    )
    live_chunks = [json.loads(event["chunk"]["bytes"]) for event in live_resp["body"]]
    assert live_chunks, "positive control: the live model must yield at least one stream chunk"
    # The live stream's events arrive in the declared order: messageStart, then content blocks
    # (text deltas, each block closed by contentBlockStop), then messageStop; the deltas
    # concatenate to the reply.
    events = [k for c in live_chunks for k in c if k != "amazon-bedrock-invocationMetrics"]
    assert events[0] == "messageStart", f"stream must open with messageStart, got {events!r}"
    assert events.count("messageStop") == 1, f"exactly one messageStop expected: {events!r}"
    stop = events.index("messageStop")
    blocks = events[1:stop]
    assert "contentBlockDelta" in blocks and blocks[-1] == "contentBlockStop", (
        f"content deltas must arrive before messageStop, the last block closed: {events!r}"
    )
    assert set(blocks) <= {"contentBlockStart", "contentBlockDelta", "contentBlockStop"}, events
    assert "contentBlockDelta" not in events[stop:], f"no delta after messageStop: {events!r}"
    text = "".join(
        c["contentBlockDelta"]["delta"].get("text", "") for c in live_chunks if "contentBlockDelta" in c
    )
    assert "PONG" in text.upper(), f"the concatenated deltas must carry the reply, got {text!r}"

    # The refusal: the retired model is rejected, specifically, every time, on the data plane.
    code, message = _invoke_stream_error(brt, _EOL_MODEL_ID)
    assert code == "ResourceNotFoundException", (
        f"expected the retired model to be refused with ResourceNotFoundException, "
        f"got {code!r} ({message!r})"
    )
    assert message == 'This model version has reached the end of its life. Please refer to the AWS documentation for more details.', (
        f"expected the refusal to name end-of-life specifically, not a generic not-found; "
        f"got {message!r}"
    )

    # An independent read, through a DIFFERENT operation, confirms the same withdrawal.
    get_code, get_message = _get_foundation_model_error(bedrock, _EOL_MODEL_ID)
    assert get_code == "ResourceNotFoundException", (
        f"GetFoundationModel should refuse the retired model the same way InvokeModel* does; "
        f"got {get_code!r} ({get_message!r})"
    )
    assert get_message == 'This model version has reached the end of its life. Use an active model version instead. Refer to the Model lifecycle topic in the AWS documentation for more details.', (
        f"expected GetFoundationModel's refusal to also name end-of-life; got {get_message!r}"
    )

    # Effect-absent: the retired model does not appear in the account's live catalog at all.
    summaries = bedrock.list_foundation_models()["modelSummaries"]
    matches = [m["modelId"] for m in summaries if m["modelId"] == _EOL_MODEL_ID]
    assert not matches, (
        f"expected {_EOL_MODEL_ID} to be absent from ListFoundationModels; found it: {matches!r}"
    )


def _invoke_stream_error(client, model_id):
    from botocore.exceptions import ClientError

    try:
        resp = client.invoke_model_with_response_stream(
            modelId=model_id,
            body=json.dumps(
                {
                    "inputText": "Write a short five-sentence story about a lighthouse keeper.",
                    "textGenerationConfig": {"maxTokenCount": 300, "temperature": 0.7},
                }
            ),
            contentType="application/json",
            accept="application/json",
        )
        for _ in resp["body"]:
            pass
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"{model_id} was invoked successfully; it should have been refused as end-of-life")


def _get_foundation_model_error(client, model_id):
    from botocore.exceptions import ClientError

    try:
        client.get_foundation_model(modelIdentifier=model_id)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"GetFoundationModel({model_id}) succeeded; it should have been refused as end-of-life")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
