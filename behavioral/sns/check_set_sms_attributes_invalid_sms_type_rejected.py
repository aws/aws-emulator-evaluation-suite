"""set-sms-attributes-invalid-sms-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-sms-attributes-invalid-sms-type-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:sns-sms-attributes")
def run(ctx) -> None:
    """SetSMSAttributes refuses DefaultSMSType=Marketing (the legal values are Promotional
    and Transactional) and the account's DefaultSMSType reads back exactly as it was.
    """
    sns = ctx.client("sns")
    before = sns.get_sms_attributes(attributes=["DefaultSMSType"])["attributes"]

    code, message = _error(lambda: sns.set_sms_attributes(attributes={"DefaultSMSType": "Marketing"}))
    assert code == "InvalidParameter", f"DefaultSMSType=Marketing gave {code!r}"
    assert message == "DefaultSMSType is invalid", f"unexpected message for DefaultSMSType=Marketing: {message!r}"

    after = sns.get_sms_attributes(attributes=["DefaultSMSType"])["attributes"]
    assert after.get("DefaultSMSType") != "Marketing", "the refused value must not be stored"
    assert after == before, (
        f"the refused SetSMSAttributes must leave DefaultSMSType as it was: before={before!r} after={after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
