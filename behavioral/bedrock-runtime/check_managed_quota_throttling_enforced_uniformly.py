"""managed-quota-throttling-enforced-uniformly."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-quota-throttling-enforced-uniformly"
GROUP = "server-side"
SERVICES = ["bedrock-runtime"]

TEXT_MODEL = "amazon.nova-lite-v1:0"
_CONCURRENCY = 20


def _nova_body(text: str) -> bytes:
    return json.dumps(
        {"messages": [{"role": "user", "content": [{"text": text}]}], "inferenceConfig": {"maxTokens": 10, "temperature": 0, "topP": 1}}
    ).encode("utf-8")


def _invoke_once(ctx, idx: int) -> tuple[str, int, object]:
    bedrock = ctx.client("bedrock-runtime")
    try:
        resp = bedrock.invoke_model(
            modelId=TEXT_MODEL, body=_nova_body(f"Echo the number {idx}."), contentType="application/json"
        )
        body = json.loads(resp["body"].read())
        return "success", idx, body["output"]["message"]["content"][0]["text"]
    except ClientError as err:
        return err.response["Error"]["Code"], idx, None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A concurrent InvokeModel burst yields only successes or ThrottlingException, and each
    success echoes its own number, so no output is corrupted or cross-delivered."""
    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        futures = [pool.submit(_invoke_once, ctx, i) for i in range(_CONCURRENCY)]
        outcomes = [f.result() for f in as_completed(futures)]

    codes = {code for code, _, _ in outcomes}
    allowed = {"success", "ThrottlingException"}
    assert codes <= allowed, f"unexpected outcome codes under concurrent load: {codes - allowed}"

    successes = [(idx, text) for code, idx, text in outcomes if code == "success"]
    assert len(successes) >= 1, "expected at least one successful call in a burst of 20"
    for idx, text in successes:
        assert isinstance(text, str) and text.strip() != "", "each success must carry real output content"
        assert str(idx) in text, (
            f"call {idx} must echo its own number back -- got {text!r}, which does not "
            "contain it (a cross-delivered or corrupted response under load)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
