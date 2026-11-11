"""get-caller-identity-unsigned-request-rejected."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import requests

from behavioral_harness import tags

CHECK = "get-caller-identity-unsigned-request-rejected"
GROUP = "overly-permissive"
SERVICES = ["sts"]

_MISSING_AUTH_MESSAGE = "Request is missing Authentication Token"


@tags("axis:rejection", "cap:unclassified", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A GetCallerIdentity request carrying no SigV4 authentication at all is refused HTTP 403
    with MissingAuthenticationToken, not served as an anonymous call.
    """
    sts = ctx.client("sts")
    endpoint = sts.meta.endpoint_url

    def _parse(body: str):
        try:
            return ET.fromstring(body)
        except ET.ParseError as exc:
            raise AssertionError(f"the refusal body is not XML ({exc}): {body[:200]!r}") from None

    def _identity(response: dict) -> dict:
        return {k: response[k] for k in ("Arn", "Account", "UserId")}

    # Positive control: the ordinary signed call succeeds first, on the same endpoint.
    control = _identity(sts.get_caller_identity())
    assert control["Account"], f"positive control failed: {control!r}"

    resp = requests.post(
        endpoint,
        data="Action=GetCallerIdentity&Version=2011-06-15",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
        verify=ctx.http_verify,
    )
    assert resp.status_code == 403, (
        f"an entirely unsigned GetCallerIdentity request was not refused: expected HTTP 403, "
        f"got {resp.status_code} with body starting {resp.text[:200]!r}"
    )
    root = _parse(resp.text)
    code = root.findtext(".//{*}Error/{*}Code")
    assert code == "MissingAuthenticationToken", (
        f"wrong error code for an unsigned request: expected 'MissingAuthenticationToken', "
        f"got {code!r} (body {resp.text[:200]!r})"
    )
    message = root.findtext(".//{*}Error/{*}Message")
    assert message == _MISSING_AUTH_MESSAGE, (
        f"wrong error message for an unsigned request: expected {_MISSING_AUTH_MESSAGE!r}, got {message!r}"
    )

    # The refusal discloses no identity.
    assert root.find(".//{*}Account") is None, (
        f"the refusal of an unsigned request disclosed an Account field: {resp.text[:200]!r}"
    )
    assert control["Account"] not in resp.text, (
        "the account id appeared in the body of a 403 for an unsigned request"
    )

    # The endpoint stays healthy for a properly signed call made right after the refusal.
    restored = _identity(sts.get_caller_identity())
    assert restored == control, (
        f"the signed call stopped matching after the unsigned one was refused: "
        f"expected {control!r}, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
