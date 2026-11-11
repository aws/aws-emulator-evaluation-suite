"""concurrent-generate-mac-same-key-no-cross-talk."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-generate-mac-same-key-no-cross-talk"
GROUP = "concurrency"
SERVICES = ["payment-cryptography-data"]

N = 8


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent GenerateMac calls on one HMAC key with distinct messages return distinct MACs, each
    MAC verifies against its own message and fails verification against another message with
    VerificationFailedException "Mac verification failed." and Reason INVALID_MAC."""
    key = _create_mac_key(ctx)
    data = ctx.client("payment-cryptography-data")
    messages = [f"{i:02x}" * 8 for i in range(N)]

    def _generate(message):
        resp = data.generate_mac(
            KeyIdentifier=key["arn"],
            MessageData=message,
            GenerationAttributes={"Algorithm": "HMAC"},
        )
        return message, resp["Mac"]

    with ThreadPoolExecutor(max_workers=N) as pool:
        results = list(pool.map(_generate, messages))

    macs = [mac for _, mac in results]
    assert len(set(macs)) == N, "distinct messages produced colliding MACs"

    for message, mac in results:
        # Each MAC must verify against its own message.
        data.verify_mac(
            KeyIdentifier=key["arn"],
            MessageData=message,
            Mac=mac,
            VerificationAttributes={"Algorithm": "HMAC"},
        )
        # And must NOT verify against any other thread's message (no cross-talk).
        for other_message, _ in results:
            if other_message == message:
                continue
            err = _client_error(
                lambda m=other_message, mac=mac: data.verify_mac(
                    KeyIdentifier=key["arn"],
                    MessageData=m,
                    Mac=mac,
                    VerificationAttributes={"Algorithm": "HMAC"},
                ),
                f"MAC for message {message!r} verified against unrelated message "
                f"{other_message!r} (cross-talk)",
            )
            code = err.response["Error"]["Code"]
            assert code == "VerificationFailedException", (
                f"MAC for message {message!r} checked against {other_message!r}: got error "
                f'{code!r}, expected "VerificationFailedException"'
            )
            msg = err.response["Error"]["Message"]
            assert msg == "Mac verification failed.", (
                f"expected message 'Mac verification failed.', got {msg!r}"
            )
            assert err.response.get("Reason") == "INVALID_MAC", (
                f"expected Reason=INVALID_MAC, got {err.response.get('Reason')!r}"
            )


def _client_error(fn, what):
    """The ClientError fn() raises; a success is the defect under test and fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"{what}: the call succeeded and returned {result!r}")


def _create_mac_key(ctx):
    pc = ctx.client("payment-cryptography")
    tag_value = ctx.unique_name("sim2real-val-")
    resp = pc.create_key(
        Exportable=True,
        KeyAttributes={
            "KeyAlgorithm": "HMAC_SHA256",
            "KeyClass": "SYMMETRIC_KEY",
            "KeyUsage": "TR31_M7_HMAC_KEY",
            "KeyModesOfUse": {"Generate": True, "Verify": True},
        },
        Tags=[{"Key": "sim2real-env", "Value": tag_value}],
    )
    key = resp["Key"]
    arn = key["KeyArn"]

    def _cleanup():
        try:
            pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"arn": arn, "kcv": key["KeyCheckValue"]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
