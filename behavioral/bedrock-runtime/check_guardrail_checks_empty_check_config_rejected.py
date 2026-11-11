"""guardrail-checks-empty-check-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "guardrail-checks-empty-check-config-rejected"
GROUP = 'guardrail_checks_rejected'
SERVICES = ['bedrock-runtime']

_TEXT = "My email is jdoe@example.com."


def _error(fn):
    """Return (code, message) for a ClientError; raise if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("call was expected to be refused but returned success")


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An empty `checks` object is refused with ValidationException and no results or usage.
    All its members are optional, so `{}` is valid in shape and only the service refuses it."""
    rt = ctx.client("bedrock-runtime")
    messages = [{"role": "user", "content": [{"text": _TEXT}]}]

    # Positive control: the payload, the credentials and the message shape are all sound.
    control = rt.invoke_guardrail_checks(
        messages=messages,
        checks={"sensitiveInformation": {"entities": [{"type": "EMAIL"}]}},
    )
    assert [e["type"] for e in control["results"]["sensitiveInformation"]["results"]] == ["EMAIL"], (
        f"positive control failed to detect the email in {_TEXT!r}: "
        f"{control['results']['sensitiveInformation']['results']!r}"
    )
    assert control["usage"]["sensitiveInformation"]["textUnits"] == 1, (
        f"positive control billed {control['usage']['sensitiveInformation']['textUnits']!r} "
        f"text units for one short message"
    )

    # Break exactly one thing: drop every configured check type.
    code, message = _error(
        lambda: rt.invoke_guardrail_checks(messages=messages, checks={})
    )
    assert code == "ValidationException", (
        f"an empty checks object must be a ValidationException, got {code!r}"
    )
    assert message == "At least one check type must be configured", (
        f"unexpected refusal message for an empty checks object: {message!r}"
    )

    # The effect is absent: the refusal carries no evaluated result and no billable usage.
    try:
        rt.invoke_guardrail_checks(messages=messages, checks={})
    except ClientError as exc:
        body = exc.response
    assert "results" not in body, (
        f"the refused response carried a results member: {body.get('results')!r}"
    )
    assert "usage" not in body, (
        f"the refused response carried a usage member: {body.get('usage')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
