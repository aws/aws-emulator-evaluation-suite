"""concurrent-delete-encoder-configuration-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-delete-encoder-configuration-race"
GROUP = "concurrency"
SERVICES = ["ivs-realtime"]

NOT_FOUND_MESSAGE = "Resource: {arn} not found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When N callers race to DeleteEncoderConfiguration on the very same resource,
    exactly one delete succeeds and every other racer observes ResourceNotFoundException
    -- deletion is not silently idempotent-successful for everyone."""
    client = ctx.client("ivs-realtime")
    arn = client.create_encoder_configuration(
        name=ctx.unique_name("sim2real-encoder"), tags={"sim2real": CHECK}
    )["encoderConfiguration"]["arn"]
    ctx.on_cleanup(lambda: _safe_delete(client, arn))

    racer_count = 6

    def _racer(_: int) -> dict | None:
        """One racer's outcome: None when its delete succeeded, else the botocore Error dict."""
        from botocore.exceptions import ClientError

        try:
            client.delete_encoder_configuration(arn=arn)
        except ClientError as err:
            return err.response["Error"]
        return None

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        outcomes = [f.result() for f in as_completed(futures)]

    expected_message = NOT_FOUND_MESSAGE.format(arn=arn)
    successes = [o for o in outcomes if o is None]
    not_founds = [
        o for o in outcomes
        if o is not None and o.get("Code") == "ResourceNotFoundException"
        and o.get("Message") == expected_message
    ]
    assert len(successes) == 1, f"expected exactly 1 successful delete, got {len(successes)}: {outcomes!r}"
    assert len(not_founds) == racer_count - 1, (
        f"expected {racer_count - 1} ResourceNotFoundException {expected_message!r}, got {outcomes!r}"
    )

    # Final state: resource is gone for good.
    final = _client_error(lambda: client.get_encoder_configuration(arn=arn))
    assert final.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from get after the race settled, got {final!r}"
    )
    assert final.get("Message") == expected_message, final

    # The dead id also rejects a second delete, not just a read.
    redelete = _client_error(lambda: client.delete_encoder_configuration(arn=arn))
    assert redelete.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting an already-gone arn, got {redelete!r}"
    )
    assert redelete.get("Message") == expected_message, redelete


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(client, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_encoder_configuration(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
