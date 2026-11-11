"""presigned-get-caller-identity-url-is-authenticated-by-query-string-sigv4."""
from __future__ import annotations

import re
import time

import requests

from behavioral_harness import tags

CHECK = "presigned-get-caller-identity-url-is-authenticated-by-query-string-sigv4"
GROUP = "data-plane"
SERVICES = ["sts"]

_LONG_EXPIRES_S = 900
_SHORT_EXPIRES_S = 5
# Hold past the short URL's stated expiry; real STS keeps honouring it well beyond this.
_PAST_EXPIRY_WAIT_S = 30.0


@tags("axis:rejection", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """STS honours presigned (query-string SigV4) GetCallerIdentity with the signed-POST identity,
    refuses a tampered signature with SignatureDoesNotMatch, and does not enforce X-Amz-Expires.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-authentication-methods.html
    """
    sts = ctx.client("sts")

    # `verify` follows the harness so a self-signed endpoint is reached like ctx.client reaches it.
    def _get(url):
        """(status, body-text) for a plain HTTPS GET. An HTTP error status is an OBSERVATION
        here, not an exception, so 403 bodies stay readable."""
        resp = requests.get(url, timeout=20, verify=ctx._verify_ssl, allow_redirects=False)
        return resp.status_code, resp.text

    def _xml(body, element):
        """The text of the first <element> in `body`, or None. Deliberately returns None rather
        than "" so a missing element can never compare equal to a real value."""
        found = re.search(rf"<{element}>([^<]*)</{element}>", body)
        return found.group(1) if found else None

    def _identity_from_xml(body):
        return {
            "Arn": _xml(body, "Arn"),
            "Account": _xml(body, "Account"),
            "UserId": _xml(body, "UserId"),
        }

    def _presign(expires_in):
        return sts.generate_presigned_url(
            "get_caller_identity", Params={}, ExpiresIn=expires_in, HttpMethod="GET"
        )

    def _corrupt_signature(url):
        """Flip exactly one hex digit of X-Amz-Signature and change nothing else, so the ONLY
        difference between the accepted and the refused request is the signature bytes."""
        found = re.search(r"X-Amz-Signature=([0-9a-fA-F]+)", url)
        assert found is not None, (
            f"the presigned URL carries no X-Amz-Signature query parameter, so query-string "
            f"SigV4 was never applied: {url.split('?')[0]}?<{len(url)} chars>"
        )
        sig = found.group(1)
        assert len(sig) >= 2, f"X-Amz-Signature is implausibly short ({len(sig)} chars)"
        broken = sig[:-1] + ("1" if sig[-1] == "0" else "0")
        assert broken != sig, f"signature corruption was a no-op on a {len(sig)}-char signature"
        return url.replace(f"X-Amz-Signature={sig}", f"X-Amz-Signature={broken}")

    def _confirm_honoured_for(url, *, duration_s, interval_s, expected_identity):
        """Read `url` across a `duration_s` window, asserting EVERY read is HTTP 200 with the
        expected identity, so a mid-window refusal is caught where it happens."""
        deadline = time.monotonic() + duration_s
        last = None
        while True:
            last = _get(url)
            status, body = last
            assert status == 200, (
                f"a presigned GetCallerIdentity URL was refused inside a {duration_s:.0f}s "
                f"hold window: expected HTTP 200 (real STS does not enforce X-Amz-Expires on "
                f"this operation), got {status} with body starting {body[:200]!r}"
            )
            assert _identity_from_xml(body) == expected_identity, (
                f"a still-honoured presigned GET returned a different identity mid-hold: "
                f"expected {expected_identity}, got {_identity_from_xml(body)}"
            )
            if time.monotonic() >= deadline:
                return last
            time.sleep(interval_s)

    # Expected identity comes from the ordinary signed-POST path in this run, never a literal.
    sdk_identity = sts.get_caller_identity()
    expected = {k: sdk_identity[k] for k in ("Arn", "Account", "UserId")}

    # --- BEAT 1: POSITIVE CONTROL. Query-string SigV4 is honoured and returns the SAME identity.
    long_url = _presign(_LONG_EXPIRES_S)
    assert "X-Amz-Signature=" in long_url, (
        "the presigned URL is not query-string signed: expected an X-Amz-Signature query "
        f"parameter, got the parameter names "
        f"{sorted(p.split('=')[0] for p in long_url.partition('?')[2].split('&') if p)}"
    )
    status, body = _get(long_url)
    assert status == 200, (
        f"a freshly presigned GetCallerIdentity URL was not honoured: expected HTTP 200, "
        f"got {status} with body starting {body[:200]!r}"
    )
    presigned_identity = _identity_from_xml(body)
    assert presigned_identity == expected, (
        f"the presigned GET returned a different identity than the signed POST: "
        f"expected {expected}, got {presigned_identity}"
    )

    # --- BEAT 2 and 3: break EXACTLY ONE thing (one hex digit of the signature) and demand the
    # SPECIFIC refusal.
    tampered_url = _corrupt_signature(long_url)
    tampered_status, tampered_body = _get(tampered_url)
    assert tampered_status == 403, (
        f"a presigned URL with one corrupted signature digit was not refused: expected HTTP 403, "
        f"got {tampered_status} with body starting {tampered_body[:200]!r}"
    )
    tampered_code = _xml(tampered_body, "Code")
    assert tampered_code == "SignatureDoesNotMatch", (
        f"wrong error code for a corrupted query-string signature: expected "
        f"'SignatureDoesNotMatch', got {tampered_code!r} (body {tampered_body[:200]!r})"
    )

    # --- BEAT 4: the effect is ABSENT -- no part of the identity leaked into the refusal.
    leaked = _identity_from_xml(tampered_body)
    assert all(v is None for v in leaked.values()), (
        f"the refusal of a corrupted signature still disclosed identity fields: {leaked}"
    )
    assert expected["Account"] not in tampered_body, (
        "the account id appeared in the body of a 403 for a corrupted signature"
    )

    # --- BEAT 5: RESTORE. The identical, untampered URL is still honoured, which is what
    # separates "rejects a bad signature" from "rejects every presigned URL".
    restored_status, restored_body = _get(long_url)
    assert restored_status == 200, (
        f"the untampered presigned URL stopped being honoured after the tampered one was "
        f"refused: expected HTTP 200, got {restored_status} "
        f"with body starting {restored_body[:200]!r}"
    )
    assert _identity_from_xml(restored_body) == expected, (
        f"the restored presigned GET returned a different identity: expected {expected}, "
        f"got {_identity_from_xml(restored_body)}"
    )

    # --- BEAT 6: two URLs minted together differ ONLY in X-Amz-Expires. Real STS does not
    # enforce X-Amz-Expires on GetCallerIdentity, so the short one stays honoured past its window;
    # an S3-style expiry check diverges from AWS here.
    short_url = _presign(_SHORT_EXPIRES_S)
    twin_long_url = _presign(_LONG_EXPIRES_S)

    short_status, short_body = _get(short_url)
    assert short_status == 200, (
        f"the short-lived presigned URL was not honoured while still inside its "
        f"{_SHORT_EXPIRES_S}s window: expected HTTP 200, got {short_status} "
        f"with body starting {short_body[:200]!r}"
    )

    _confirm_honoured_for(
        short_url,
        duration_s=_PAST_EXPIRY_WAIT_S,
        interval_s=2.0,
        expected_identity=expected,
    )

    # --- The 900s twin minted alongside is still honoured, so the endpoint itself is healthy.
    twin_status, twin_body = _get(twin_long_url)
    assert twin_status == 200, (
        f"the {_LONG_EXPIRES_S}s presigned URL minted at the same instant as the "
        f"{_SHORT_EXPIRES_S}s one was refused: expected HTTP 200, got {twin_status} "
        f"with body starting {twin_body[:200]!r}"
    )
    assert _identity_from_xml(twin_body) == expected, (
        f"the still-valid presigned GET returned a different identity: expected {expected}, "
        f"got {_identity_from_xml(twin_body)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
