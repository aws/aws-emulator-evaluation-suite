"""delete-transformer-nonexistent-fails."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-transformer-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTransformer removes a configured transformer, then on the group with none raises
    ResourceNotFoundException with the exact message naming the group; putting a transformer back makes the
    delete succeed again."""
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    )

    transformer_config = [{"parseJSON": {}}]

    # Positive control: DeleteTransformer succeeds when a transformer really is configured,
    # so a target that always rejects DeleteTransformer cannot pass this check.
    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=transformer_config)
    logs.delete_transformer(logGroupIdentifier=log_group_name)

    # Effect-absent, via an independent read: the transformer must actually be gone before
    # the negative below means anything.
    kind, value = _poll_until_transformer_absent(
        lambda: logs.get_transformer(logGroupIdentifier=log_group_name)
    )
    assert (kind == "error" and value == "ResourceNotFoundException") or (
        kind == "config" and not value
    ), f"expected the transformer removed above to be gone, got {kind}={value!r}"

    # Negative: with no transformer configured, DeleteTransformer fails.
    error = _expect_error(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = f"Transformer does not exist on log group '{log_group_name}'"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Restore: putting a transformer back and deleting it again must succeed identically,
    # proving the rejection above tracked the absent state rather than a permanent break.
    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=transformer_config)
    logs.delete_transformer(logGroupIdentifier=log_group_name)


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is not None:
            return response.get("Error", {})
        raise
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until_transformer_absent(fn, timeout: float = 30.0, interval: float = 2.0):
    """DeleteTransformer's removal is not always immediately visible to GetTransformer, and on
    real AWS the removal can surface either as a ResourceNotFoundException or as GetTransformer
    continuing to succeed with an empty transformerConfig. Poll for either signal within a
    bounded window rather than assuming a single specific error code, and return
    (kind, value) where kind is "error" (value = error code) or "config" (value =
    transformerConfig, possibly empty/None)."""
    import time

    deadline = time.monotonic() + timeout
    last_result = (None, None)
    while True:
        try:
            resp = fn()
            config = resp.get("transformerConfig")
            last_result = ("config", config)
            if not config:
                return last_result
        except Exception as exc:  # botocore.exceptions.ClientError
            resp_err = getattr(exc, "response", None)
            code = resp_err.get("Error", {}).get("Code") if isinstance(resp_err, dict) else None
            if code is None:
                raise
            last_result = ("error", code)
            if code == "ResourceNotFoundException":
                return last_result
        if time.monotonic() >= deadline:
            return last_result
        time.sleep(interval)


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
        if code not in ("ResourceNotFoundException", None):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
