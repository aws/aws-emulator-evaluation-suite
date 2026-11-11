"""provisioned-limit-update-concurrent-modification-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "provisioned-limit-update-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

_SAME_VALUE = "Requested value is the same as the current provisioned limit"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cognito-idp-provisioned-limits")
def run(ctx) -> None:
    """UpdateProvisionedLimit refuses the current value with InvalidParameterException; two concurrent
    updates end in one of the requested values, or with no Service Quotas headroom the raise fails
    with ServiceQuotaExceededException and its message and the limit is unchanged."""
    cognito = ctx.client("cognito-idp")
    limit_definition = {"LimitClass": "API_CATEGORY", "Attributes": {"Category": "UserCreation"}}

    def _get_value():
        return cognito.get_provisioned_limit(LimitDefinition=limit_definition)["Limit"][
            "ProvisionedLimitValue"
        ]

    def _set_value(value):
        return cognito.update_provisioned_limit(
            LimitDefinition=limit_definition, RequestedLimitValue=value
        )["Limit"]["ProvisionedLimitValue"]

    def _error_code(exc):
        return exc.response["Error"]["Code"]

    def _error_message(exc):
        return exc.response["Error"].get("Message")

    def _write_current(value):
        """Provision ``value`` explicitly: a category never written accepts the value it reports
        once, and a provisioned one refuses an unchanged value as below."""
        try:
            _set_value(value)
        except ClientError as e:
            if (_error_code(e), _error_message(e)) != ("InvalidParameterException", _SAME_VALUE):
                raise

    orig_value = _get_value()
    probe_value = orig_value + 1

    ctx.on_cleanup(lambda: _write_current(orig_value))
    _write_current(orig_value)

    # Confirmed real behaviour: a same-value request is rejected as a no-op, not silently
    # accepted -- assert that directly before relying on it to reason about racing values.
    try:
        _set_value(orig_value)
    except ClientError as e:
        assert _error_code(e) == "InvalidParameterException", (
            f"a same-value UpdateProvisionedLimit({orig_value}) failed with "
            f"{_error_code(e)}, expected InvalidParameterException"
        )
        assert _error_message(e) == _SAME_VALUE, (
            _error_message(e)
        )
    else:
        raise AssertionError(
            f"a same-value UpdateProvisionedLimit({orig_value}) unexpectedly succeeded -- "
            "expected it to be rejected as a no-op request"
        )

    try:
        _set_value(probe_value)
    except ClientError as e:
        if _error_code(e) != "ServiceQuotaExceededException":
            raise AssertionError(
                f"raising ProvisionedLimitValue by 1 RPS (to {probe_value}) failed with "
                f"{_error_code(e)}, expected either success or ServiceQuotaExceededException"
            ) from e
        # orig_value is within the ceiling and one above it is refused: the ceiling is orig_value.
        expected = f"Requested value {probe_value} exceeds Service Quota ceiling of {orig_value}"
        assert _error_message(e) == expected, (_error_message(e), expected)
        after = _get_value()
        assert after == orig_value, (
            f"ProvisionedLimitValue is {after} after a rejected raise attempt -- expected "
            f"it unchanged at {orig_value} (effect was not absent despite the refusal)"
        )
        return

    # Headroom exists (rare): current is now probe_value, so orig_value (legal a moment
    # ago) and a further raise are the two distinct, both-non-current values to race.
    value_up = probe_value + 1

    def _race(value):
        try:
            return ("ok", _set_value(value), None)
        except ClientError as e:
            return ("error", _error_code(e), _error_message(e))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_down = pool.submit(_race, orig_value)
        fut_up = pool.submit(_race, value_up)
        kind_down, result_down, _ = fut_down.result()
        kind_up, result_up, message_up = fut_up.result()

    assert kind_down == "ok" and result_down in (orig_value, value_up), (
        f"racing decrease to {orig_value} returned {(kind_down, result_down)}, expected "
        f"an 'ok' result in ({orig_value}, {value_up})"
    )
    if kind_up == "error":
        assert result_up == "ServiceQuotaExceededException", (
            f"racing increase to {value_up} failed with {result_up}, expected success or "
            "ServiceQuotaExceededException"
        )
        # probe_value was accepted and one above it is refused: the ceiling is probe_value.
        expected = f"Requested value {value_up} exceeds Service Quota ceiling of {probe_value}"
        assert message_up == expected, (message_up, expected)
        expected_final = {orig_value}
    else:
        assert result_up in (orig_value, value_up), (
            f"racing increase returned {result_up}, expected one of ({orig_value}, {value_up})"
        )
        expected_final = {orig_value, value_up}

    final_value = _get_value()
    assert final_value in expected_final, (
        f"final ProvisionedLimitValue {final_value} is not among the legitimate racing "
        f"outcomes {sorted(expected_final)} -- state was corrupted under contention"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
