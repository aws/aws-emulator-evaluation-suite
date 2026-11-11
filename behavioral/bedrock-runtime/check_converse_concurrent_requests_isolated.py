"""converse-concurrent-requests-isolated."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "converse-concurrent-requests-isolated"
GROUP = "concurrency"
SERVICES = ["bedrock-runtime"]

MODEL_ID = "amazon.nova-lite-v1:0"
SECRETS = ["48213", "91007", "36542", "70298", "15966"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent, stateless Converse calls each carrying a distinct secret number never
    cross-talk: every response contains its own secret and none of the others' secrets."""
    brt = ctx.client("bedrock-runtime")

    def _ask(secret: str) -> str:
        resp = brt.converse(
            modelId=MODEL_ID,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                f"My locker combination number is {secret}. Please confirm "
                                "my locker combination number back to me in your reply."
                            )
                        }
                    ],
                }
            ],
            inferenceConfig={"maxTokens": 32, "temperature": 0},
        )
        return "".join(b["text"] for b in resp["output"]["message"]["content"] if "text" in b)

    with ThreadPoolExecutor(max_workers=len(SECRETS)) as pool:
        results = list(pool.map(_ask, SECRETS))

    for secret, text in zip(SECRETS, results):
        assert secret in text, f"expected {secret} in response, got: {text!r}"
        others = [s for s in SECRETS if s != secret]
        leaked = [o for o in others if o in text]
        assert not leaked, f"response for {secret} leaked other secrets {leaked}: {text!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
