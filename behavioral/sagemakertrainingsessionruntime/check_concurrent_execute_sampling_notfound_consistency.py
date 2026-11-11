"""concurrent-execute-sampling-notfound-consistency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-execute-sampling-notfound-consistency"
GROUP = "concurrency"
SERVICES = ["sagemakertrainingsessionruntime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Many concurrent ExecuteSamplingOperation calls against the same never-created training
    session each return the identical ResourceNotFoundException outcome independently, never a
    success and never a ConflictException from racing against each other.
    """
    client = ctx.client("sagemakertrainingsessionruntime")
    session_name = ctx.unique_name("sim2real-stsr-sess-")
    racer_count = 8

    def _racer(i: int):
        try:
            client.execute_sampling_operation(
                trainingSessionName=session_name,
                operationConfig={
                    "sample": {
                        "prompt": {"chunks": [{"tokens": [i + 1], "type": "encoded_text"}]},
                        "numSamples": 1,
                        "samplingParams": {"maxTokens": 512},
                    }
                },
            )
            return "success", None
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message")

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        outcomes = [f.result() for f in as_completed(futures)]

    assert len(outcomes) == racer_count, (
        f"expected {racer_count} racer outcomes, got {len(outcomes)}: {outcomes}"
    )
    want = (
        "ResourceNotFoundException",
        f"Session not found: {session_name}-{ctx.account}-{ctx.region}",
    )
    for outcome in outcomes:
        assert outcome == want, (
            f"expected every concurrent racer against a never-created session to get "
            f"{want!r} independently, got {outcome!r} among {outcomes}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
