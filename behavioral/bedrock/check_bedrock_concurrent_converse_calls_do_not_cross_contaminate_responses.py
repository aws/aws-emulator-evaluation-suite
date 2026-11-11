"""bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses."""
from __future__ import annotations

import concurrent.futures
import random
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bedrock-concurrent-converse-calls-do-not-cross-contaminate-responses"
GROUP = 'concurrency'
SERVICES = ['bedrock']

# Pinned, not env-read: this model follows the echo-a-token instruction exactly under 8-way
# concurrency, which is what lets the check match answers to requests.
MODEL_ID = "amazon.nova-lite-v1:0"

_N = 8
_MAX_THROTTLE_RETRIES = 5


def _converse_echo(rt, nonce):
    """One inference, with a bounded backoff retry on throttling ONLY.

    On-demand Bedrock throughput is account-limited, so a throttle is an environment condition and
    not the behaviour under test -- but an UNRETRIED throttle is a failure of this check, never a
    skip, because "the account was busy" and "the emulator lost a response" must not be reported
    the same way.
    """
    for attempt in range(_MAX_THROTTLE_RETRIES):
        try:
            resp = rt.converse(
                modelId=MODEL_ID,
                messages=[{"role": "user", "content": [{
                    "text": "Reply with exactly this token and nothing else, no punctuation "
                            "and no commentary: " + nonce}]}],
                inferenceConfig={"maxTokens": 30, "temperature": 0.0},
            )
            return "".join(b.get("text", "") for b in resp["output"]["message"]["content"])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "ThrottlingException" or attempt == _MAX_THROTTLE_RETRIES - 1:
                raise
            time.sleep(min(2 ** attempt, 8) + random.random())
    raise AssertionError("unreachable")


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c3")
def run(ctx) -> None:
    """Eight simultaneous Converse calls, each asking to echo its own nonce, each get back an
    answer carrying their own nonce and none of the others: responses are isolated per request.
    """
    rt = ctx.client("bedrock-runtime")
    nonces = ["zq" + uuid.uuid4().hex[:10] for _ in range(_N)]
    assert len(set(nonces)) == _N, f"nonces must be distinct; got {nonces!r}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=_N) as pool:
        answers = list(pool.map(lambda n: _converse_echo(rt, n), nonces))

    assert len(answers) == _N, (
        f"all {_N} concurrent calls must return a response; got {len(answers)}: {answers!r}"
    )

    for index, (nonce, answer) in enumerate(zip(nonces, answers)):
        assert nonce in answer, (
            f"call {index} asked the model to echo {nonce!r} and got {answer!r} back -- its own "
            f"answer did not reach it. Full mapping: {list(zip(nonces, answers))!r}"
        )
        foreign = [other for other in nonces if other != nonce and other in answer]
        assert not foreign, (
            f"call {index}'s answer {answer!r} contains another call's nonce(s) {foreign!r} -- "
            f"responses crossed. Full mapping: {list(zip(nonces, answers))!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
