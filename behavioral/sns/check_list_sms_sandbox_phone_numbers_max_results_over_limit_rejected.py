"""list-sms-sandbox-phone-numbers-max-results-over-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-sms-sandbox-phone-numbers-max-results-over-limit-rejected"
GROUP = 'sms'
SERVICES = ['sns']


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListSMSSandboxPhoneNumbers refuses MaxResults=101, one past its documented 100 maximum,
    while MaxResults=100 and a call without MaxResults are both accepted.
    """
    sns = ctx.client("sns")

    # SNS answers ValidationError, not the InvalidParameterException the model declares.
    code, message = _error(lambda: sns.list_sms_sandbox_phone_numbers(MaxResults=101))
    assert code == "ValidationError", f"MaxResults=101 gave {code!r}"
    assert message == ("1 validation error detected: Value '101' at 'maxResults' failed to satisfy "
                       "constraint: Member must have value less than or equal to 100"), f"unexpected message for MaxResults=101: {message!r}"

    at_limit = sns.list_sms_sandbox_phone_numbers(MaxResults=100)
    assert isinstance(at_limit.get("PhoneNumbers"), list), (
        f"MaxResults=100 must be accepted and return PhoneNumbers, got keys {sorted(at_limit)!r}"
    )
    assert len(at_limit["PhoneNumbers"]) <= 100, "a MaxResults=100 page must hold at most 100 numbers"
    unbounded = sns.list_sms_sandbox_phone_numbers()
    assert isinstance(unbounded.get("PhoneNumbers"), list), (
        f"a call without MaxResults must be accepted, got keys {sorted(unbounded)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
