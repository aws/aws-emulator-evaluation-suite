"""ca-resource-policy-lockout-guard-classified."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "ca-resource-policy-lockout-guard-classified"
GROUP = 'error-semantics'
SERVICES = ['acm-pca']

_MIN_DELETION_DAYS = 7

# PutPolicy does not model InvalidStateException, so a PENDING_CERTIFICATE CA suffices.
# LockoutPreventedException is unreachable: PCA refuses every Deny statement earlier with
# InvalidPolicyException "Only the Allow effect is supported", so the refusals share one code
# and are told apart by their messages.
_EXPECTED_INVALID_POLICY = "InvalidPolicyException"
_EXPECTED_LOCKOUT = "InvalidPolicyException"
# The message fragment that makes the Deny refusal a DIFFERENT rule from a malformed body.
_DENY_EFFECT_MESSAGE = "Only the Allow effect is supported"



def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _err_pair(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. Real
    PCA collapses every bad resource policy onto InvalidPolicyException and distinguishes
    them in the message."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message") or ""
    raise AssertionError("call succeeded; expected a ClientError")


def _describe(ctx, ca_arn):
    return ctx.client("acm-pca").describe_certificate_authority(
        CertificateAuthorityArn=ca_arn
    )["CertificateAuthority"]


def _teardown_ca(ctx, ca_arn):
    """Ordered, retrying teardown: wait out CREATING, DISABLE if ACTIVE, DELETE with the minimum
    7-day window, and raise if the CA still cannot be deleted so a metered CA never leaks silently.
    """
    # This check attaches resource policies, so detach any survivor before deleting.
    try:
        ctx.client("acm-pca").delete_policy(ResourceArn=ca_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    pca = ctx.client("acm-pca")
    deadline = time.monotonic() + 300
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = _describe(ctx, ca_arn).get("Status")
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if last_status == "DELETED":
            return
        if last_status == "CREATING":
            time.sleep(3)
            continue
        if last_status == "ACTIVE":
            try:
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca_arn, Status="DISABLED"
                )
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(2)
            continue
        try:
            pca.delete_certificate_authority(
                CertificateAuthorityArn=ca_arn,
                PermanentDeletionTimeInDays=_MIN_DELETION_DAYS,
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InvalidStateException", "ConcurrentModificationException"):
                time.sleep(3)
                continue
            if code == "ResourceNotFoundException":
                return
            raise
    raise AssertionError(
        f"LEAKED BILLABLE RESOURCE: could not delete certificate authority {ca_arn} within "
        f"300s (last observed Status={last_status!r}). It is STILL BILLING. Delete it "
        f"manually: UpdateCertificateAuthority(Status='DISABLED') then "
        f"DeleteCertificateAuthority(PermanentDeletionTimeInDays=7)."
    )


def _create_ca(ctx, **overrides):
    """Create the cheapest CA acm-pca offers -- ROOT / RSA_2048 / SHA256WITHRSA in
    SHORT_LIVED_CERTIFICATE usage mode, never activated, never issuing -- and register its
    teardown AT CREATION TIME, before any assertion can abort the check. Retries on
    throttling: CreateCertificateAuthority has a low request-rate limit."""
    pca = ctx.client("acm-pca")
    body = {
        "CertificateAuthorityConfiguration": {
            "KeyAlgorithm": "RSA_2048",
            "SigningAlgorithm": "SHA256WITHRSA",
            "Subject": {"CommonName": ctx.unique_name("sim2real-behav-pca-").rstrip("-")},
        },
        "CertificateAuthorityType": "ROOT",
        "UsageMode": "SHORT_LIVED_CERTIFICATE",
    }
    body.update(overrides)
    resp = None
    for attempt in range(6):
        try:
            resp = pca.create_certificate_authority(**body)
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "Throttling", "RequestLimitExceeded") and attempt < 5:
                time.sleep(2 * (attempt + 1))
                continue
            raise
    assert resp is not None, "CreateCertificateAuthority did not return after 6 attempts"
    ca_arn = resp["CertificateAuthorityArn"]
    ctx.on_cleanup(lambda: _teardown_ca(ctx, ca_arn))
    return ca_arn


def _policy_or_none(ctx, ca_arn):
    """GetPolicy, returning the parsed document or None if no policy is attached."""
    try:
        raw = ctx.client("acm-pca").get_policy(ResourceArn=ca_arn)["Policy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return None
        raise
    return json.loads(raw)


def _tag_keys(ctx, ca_arn):
    pca = ctx.client("acm-pca")
    keys, token = set(), None
    while True:
        kwargs = {"CertificateAuthorityArn": ca_arn}
        if token:
            kwargs["NextToken"] = token
        page = pca.list_tags(**kwargs)
        for tag in page.get("Tags", []):
            keys.add(tag["Key"])
        token = page.get("NextToken")
        if not token:
            return keys


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPolicy accepts a well-formed own-account Allow document but refuses a non-JSON body and a
    Statement-less body (echoed back) and a self-denying Deny document ("Only the Allow effect is
    supported"), all as InvalidPolicyException; none attaches and the CA stays mutable.

    Reference: https://docs.aws.amazon.com/privateca/latest/APIReference/API_PutPolicy.html
    """
    pca = ctx.client("acm-pca")
    timeout_s = 180
    account = ctx.client("sts").get_caller_identity()["Account"]

    # ---- Full valid setup ----
    ca_arn = _create_ca(ctx)
    ca = _poll_until(
        lambda: _describe(ctx, ca_arn),
        lambda c: c.get("Status") == "PENDING_CERTIFICATE",
        timeout_s=timeout_s, interval_s=2.0,
        description="CA reaching PENDING_CERTIFICATE",
    )
    assert ca["Status"] == "PENDING_CERTIFICATE", ca["Status"]
    assert _policy_or_none(ctx, ca_arn) is None, (
        "a freshly created CA must have no resource policy attached"
    )
    # The CA is mutable before any of the refusals, so the liveness control at the end is
    # measuring the refusals and not a pre-existing problem.
    pca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-pre", "Value": "1"}]
    )
    assert "sim2real-pre" in _tag_keys(ctx, ca_arn), "setup tag was not applied"

    # ---- Positive control: a well-formed, correctly scoped document IS accepted ----
    # Without this, the refusals could not be told apart from refusing every PutPolicy call.
    # PCA requires Resource to name the CA's own ARN (Resource="*" is refused).
    valid_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realPositiveControl",
            "Effect": "Allow",
            "Principal": {"AWS": account},
            "Action": ["acm-pca:GetCertificate"],
            "Resource": ca_arn,
        }],
    })
    pca.put_policy(ResourceArn=ca_arn, Policy=valid_policy)
    control_attached = _policy_or_none(ctx, ca_arn)
    assert (
        control_attached is not None
        and control_attached["Statement"][0]["Sid"] == "sim2realPositiveControl"
    ), (
        f"a well-formed Allow document scoped to this CA's own ARN must be accepted and "
        f"retrievable via GetPolicy, got {control_attached!r}"
    )
    pca.delete_policy(ResourceArn=ca_arn)
    assert _policy_or_none(ctx, ca_arn) is None, (
        "the positive-control policy must be removable before the refusal cases run"
    )

    # ---- Break exactly one thing (A): the body is not JSON ----
    malformed_body = "{not json at all"
    code_json, msg_json = _err_pair(
        lambda: pca.put_policy(ResourceArn=ca_arn, Policy=malformed_body)
    )
    assert code_json == _EXPECTED_INVALID_POLICY, (
        f"a non-JSON resource policy must be refused with "
        f"{_EXPECTED_INVALID_POLICY}, got {code_json!r}"
    )
    # Real PCA echoes the offending document back after an "InvalidPolicy: " prefix.
    assert msg_json == f"InvalidPolicy: {malformed_body}", (
        f"a non-JSON body must be reported as the un-parseable document itself, got "
        f"{msg_json!r}"
    )

    # ---- Break exactly one thing (B): valid JSON, not a policy ----
    # Isolates document VALIDATION from JSON parsing: an implementation that only
    # json.loads() the string accepts this one.
    no_statement = json.dumps({"Version": "2012-10-17"})
    code_shape, msg_shape = _err_pair(lambda: pca.put_policy(
        ResourceArn=ca_arn, Policy=no_statement
    ))
    assert code_shape == _EXPECTED_INVALID_POLICY, (
        f"a JSON document with no Statement is not an IAM policy and must be refused with "
        f"{_EXPECTED_INVALID_POLICY}, got {code_shape!r}"
    )
    assert msg_shape == f"InvalidPolicy: {no_statement}", (
        f"a Statement-less document must be reported as the rejected document itself, got "
        f"{msg_shape!r}"
    )
    assert _DENY_EFFECT_MESSAGE not in msg_shape, (
        f"a Statement-less document has no effect at all, so it must not be reported as an "
        f"effect violation; got {msg_shape!r}"
    )

    # ---- Break exactly one thing (C): the lockout document ----
    # Syntactically perfect and semantically catastrophic: it denies the owning account
    # every acm-pca action on this authority, including PutPolicy and DeletePolicy, which
    # would leave the CA permanently unmanageable. Refusing this is a SEPARATE rule from
    # "the document is malformed", and the separation is the fidelity signal.
    lockout = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "sim2realLockout",
            "Effect": "Deny",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "acm-pca:*",
            "Resource": ca_arn,
        }],
    }
    code_lockout, msg_lockout = _err_pair(lambda: pca.put_policy(
        ResourceArn=ca_arn, Policy=json.dumps(lockout)
    ))
    assert code_lockout == _EXPECTED_LOCKOUT, (
        f"a resource policy that denies the owning account every acm-pca action on its own "
        f"authority must be refused with {_EXPECTED_LOCKOUT}, got {code_lockout!r}"
    )
    # The discrimination assertion, moved from the code to the message: real PCA refuses a
    # self-denying document one stage EARLIER than any lockout analysis, because a resource
    # policy may only Allow. That is still a rule of its own, and it must be named -- an
    # implementation that echoes the document (the malformed-body answer) or reports a
    # generic failure cannot produce this diagnostic.
    assert msg_lockout == f"InvalidPolicy: {_DENY_EFFECT_MESSAGE}", (
        f"a Deny statement must be refused as an unsupported EFFECT "
        f"('InvalidPolicy: {_DENY_EFFECT_MESSAGE}'), got {msg_lockout!r}"
    )
    assert msg_lockout != msg_json and msg_lockout != msg_shape, (
        f"the Deny document and the malformed documents returned the same diagnostic "
        f"({msg_json!r}); the effect rule is not a distinct rule, so a customer cannot tell a "
        f"typo from a document that can never be accepted"
    )
    assert json.dumps(lockout) not in msg_lockout, (
        f"the Deny document was echoed back like a malformed body instead of being diagnosed "
        f"as an effect violation; got {msg_lockout!r}"
    )

    # ---- Effect absent: none of the three refusals attached anything ----
    attached = _policy_or_none(ctx, ca_arn)
    assert attached is None, (
        f"a refused PutPolicy attached a policy anyway: {attached!r}. The refusal was "
        f"cosmetic, and in the lockout case the CA is now unmanageable."
    )
    code_get, msg_get = _err_pair(lambda: pca.get_policy(ResourceArn=ca_arn))
    assert code_get == "ResourceNotFoundException", (
        f"with no policy attached, GetPolicy must report ResourceNotFoundException rather "
        f"than an empty document, got {code_get!r}"
    )
    assert msg_get == "Could not find policy for specified resource.", (
        f"GetPolicy no-policy message: {msg_get!r}"
    )
    # DeletePolicy succeeds on an existing CA with no policy; ResourceNotFoundException is
    # reserved for a missing CA ("Could not find specified CA"), so both halves are asserted.
    try:
        pca.delete_policy(ResourceArn=ca_arn)
    except ClientError as exc:
        raise AssertionError(
            f"deleting an absent policy from an existing authority is idempotent success on "
            f"real AWS, got {exc.response.get('Error', {})!r}"
        ) from exc
    code_get2, msg_get2 = _err_pair(lambda: pca.get_policy(ResourceArn=ca_arn))
    assert (code_get2, msg_get2) == (
        "ResourceNotFoundException",
        "Could not find policy for specified resource.",
    ), (
        "the idempotent DeletePolicy must leave the authority with no policy, so GetPolicy "
        f"must still report ResourceNotFoundException, got {(code_get2, msg_get2)!r}"
    )
    absent_ca = ca_arn.rsplit("/", 1)[0] + "/00000000-0000-4000-8000-000000000000"
    code_del_absent, msg_del_absent = _err_pair(lambda: pca.delete_policy(ResourceArn=absent_ca))
    assert code_del_absent == "ResourceNotFoundException", (
        f"DeletePolicy against an authority that does not exist must report "
        f"ResourceNotFoundException, got {code_del_absent!r}; an implementation that answers "
        f"success to every DeletePolicy cannot tell a missing policy from a missing CA"
    )
    assert msg_del_absent == "Could not find specified CA", (
        f"DeletePolicy missing-CA message: {msg_del_absent!r}"
    )

    # ---- Control: the authority is untouched and still fully mutable ----
    # If the lockout document had been silently applied, or if the refusals had wedged the
    # CA, this is what would break.
    after = _describe(ctx, ca_arn)
    assert after["Status"] == "PENDING_CERTIFICATE", (
        f"the refused PutPolicy calls moved the CA to {after['Status']!r}"
    )
    pca.tag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-post", "Value": "1"}]
    )
    keys = _tag_keys(ctx, ca_arn)
    assert {"sim2real-pre", "sim2real-post"} <= keys, (
        f"the authority is no longer mutable after the refused policy writes; tags: "
        f"{sorted(keys)}"
    )
    pca.untag_certificate_authority(
        CertificateAuthorityArn=ca_arn, Tags=[{"Key": "sim2real-post", "Value": "1"}]
    )
    assert "sim2real-post" not in _tag_keys(ctx, ca_arn), "untag did not remove the tag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
