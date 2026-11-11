"""cognito-secret-request-parameters-are-hidden-in-the-delivered-record."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-secret-request-parameters-are-hidden-in-the-delivered-record"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-idp"]

# Marks a missing audit record as a data-plane fidelity failure, not a connection error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_REDACTED = "HIDDEN_DUE_TO_SECURITY_REASONS"

# LookupEvents indexes management events in roughly 80-136 s.
_INDEX_BUDGET_S = 255.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40

# Every cognito-idp operation this check causes that could conceivably carry the password.
_SECRET_BEARING_OPERATIONS = ("InitiateAuth", "AdminSetUserPassword", "AdminCreateUser")



def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    return out


def _by_event_name(ct, name, *, start, end):
    return _lookup_all(
        ct, StartTime=start, EndTime=end, MaxResults=50,
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
    )


def _find(events, needle):
    for ev in events:
        if needle in ev.get("CloudTrailEvent", ""):
            return ev
    return None


def _delete_user_pool(idp, pool_id):
    """Idempotent teardown; DeleteUserPool also removes its app client and users."""
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c2",
)
def run(ctx) -> None:
    """InitiateAuth's CloudTrail record replaces authParameters with the string
    HIDDEN_DUE_TO_SECURITY_REASONS and never carries the password or returned tokens, while authFlow,
    clientId and a DescribeUserPool control call's arguments are recorded verbatim.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html
    """
    ct = ctx.client("cloudtrail")
    idp = ctx.client("cognito-idp")
    account = ctx.client("sts").get_caller_identity()["Account"]

    pool_name = ctx.unique_name("sim2real-behav-ctidp-")
    pool = idp.create_user_pool(
        PoolName=pool_name,
        Policies={"PasswordPolicy": {
            "MinimumLength": 8,
            "RequireUppercase": True,
            "RequireLowercase": True,
            "RequireNumbers": True,
            "RequireSymbols": True,
        }},
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool(idp, pool_id))

    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-ctidp-c-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = client["ClientId"]

    user_name = ctx.unique_name("sim2realctidpuser")
    # The password carries a run-unique token, so its absence from every record is a statement
    # about THIS secret rather than about a string that happens not to occur.
    password_token = ctx.unique_name("Ctidp").replace("-", "")
    password = f"Aa1!{password_token}"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=user_name, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=user_name, Password=password, Permanent=True
    )

    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": user_name, "PASSWORD": password},
    )
    assert "AuthenticationResult" in auth, (
        f"InitiateAuth with USER_PASSWORD_AUTH did not authenticate the user this check just "
        f"created; response keys were {sorted(auth)!r}. The redaction assertions below are only "
        f"meaningful for a request that actually carried a working password"
    )
    secrets = [
        auth["AuthenticationResult"][member]
        for member in ("AccessToken", "IdToken", "RefreshToken")
        if auth["AuthenticationResult"].get(member)
    ]
    assert secrets, (
        f"InitiateAuth returned an AuthenticationResult with no tokens: "
        f"{sorted(auth['AuthenticationResult'])!r}"
    )

    # The non-secret control call, in the same instant and to the same service.
    idp.describe_user_pool(UserPoolId=pool_id)

    window_start = emitted_at - datetime.timedelta(minutes=3)
    auth_ev = None
    control_ev = None
    polls = 0
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        if auth_ev is None:
            auth_ev = _find(
                _by_event_name(ct, "InitiateAuth", start=window_start, end=window_end),
                client_id,
            )
        if control_ev is None:
            control_ev = _find(
                _by_event_name(ct, "DescribeUserPool", start=window_start, end=window_end),
                pool_id,
            )
        if auth_ev is not None and control_ev is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert auth_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail produced no InitiateAuth record for the authentication "
        f"this check performed at {emitted_at.isoformat()} against app client {client_id!r} in "
        f"pool {pool_id!r}; {polls} polls over {waited:.0f}s found none. Real AWS indexed "
        f"management events in 80-136s in this account family. A target that does not audit "
        f"authentication attempts cannot be checked for redaction, and the absence is the more "
        f"serious defect"
    )
    assert control_ev is not None, (
        f"{DATAPLANE_MARKER}: CloudTrail produced no DescribeUserPool record for pool {pool_id!r} "
        f"after {waited:.0f}s and {polls} polls. This is the positive control -- without it, "
        f"'the password is absent from the record' cannot be distinguished from 'this target "
        f"records no request arguments at all'"
    )

    auth_record = json.loads(auth_ev["CloudTrailEvent"])
    control_record = json.loads(control_ev["CloudTrailEvent"])

    assert auth_record["eventSource"] == "cognito-idp.amazonaws.com", (
        f"the InitiateAuth record's eventSource is {auth_record.get('eventSource')!r}, expected "
        f"cognito-idp.amazonaws.com"
    )
    assert auth_record["recipientAccountId"] == account, (
        f"recipientAccountId is {auth_record.get('recipientAccountId')!r}, expected {account!r}"
    )

    # Positive control: without recorded arguments, absence of the password would pass vacuously.
    control_parameters = control_record["requestParameters"]
    assert control_parameters is not None, (
        "the DescribeUserPool record carries requestParameters=None; a successful call's "
        "arguments are recorded, so this target records nothing and the redaction assertions "
        "below would pass vacuously"
    )
    assert pool_id in json.dumps(control_parameters), (
        f"the DescribeUserPool record's requestParameters {control_parameters!r} do not carry the "
        f"pool id the call named ({pool_id!r}). Non-secret arguments are recorded verbatim"
    )

    auth_parameters = auth_record["requestParameters"]
    assert auth_parameters is not None, (
        "the InitiateAuth record carries requestParameters=None. Real AWS records the request's "
        "arguments with the secret-bearing member REDACTED, not the whole object dropped -- and "
        "dropping it loses authFlow and clientId, which every authentication-monitoring query "
        "keys on"
    )
    assert auth_parameters.get("authFlow") == "USER_PASSWORD_AUTH", (
        f"requestParameters.authFlow is {auth_parameters.get('authFlow')!r}, expected "
        f"'USER_PASSWORD_AUTH' -- a non-secret member of the same request, preserved verbatim "
        f"beside the redacted one. Members present: {sorted(auth_parameters)!r}"
    )
    assert auth_parameters.get("clientId") == client_id, (
        f"requestParameters.clientId is {auth_parameters.get('clientId')!r}, expected the app "
        f"client this check created ({client_id!r})"
    )

    # The redaction replaces the whole map with a string, so the member's type changes.
    assert "authParameters" in auth_parameters, (
        f"requestParameters has no authParameters member at all: "
        f"{sorted(auth_parameters)!r}. Real AWS keeps the member and replaces its VALUE, so a "
        f"consumer can still see that credentials were supplied; omitting it loses that fact"
    )
    recorded = auth_parameters["authParameters"]
    assert recorded == _REDACTED, (
        f"requestParameters.authParameters is {recorded!r}, expected the exact literal "
        f"{_REDACTED!r}. The request sent a map with USERNAME and PASSWORD keys; real AWS "
        f"replaces the whole map with that string"
    )
    assert isinstance(recorded, str), (
        f"requestParameters.authParameters is a {type(recorded).__name__}; the redaction replaces "
        f"the map with a plain STRING, so the member's type changes. A target that masks the "
        f"values inside the map ({{'USERNAME': ..., 'PASSWORD': '***'}}) keeps the wrong type and "
        f"fails here even though it hid the secret"
    )

    # Byte-level absence across every operation this run caused that could carry a secret.
    raw_by_operation = {}
    scan_end = datetime.datetime.now(datetime.timezone.utc)
    for operation in _SECRET_BEARING_OPERATIONS:
        events = _by_event_name(ct, operation, start=window_start, end=scan_end)
        raw_by_operation[operation] = [
            ev["CloudTrailEvent"]
            for ev in events
            if client_id in ev.get("CloudTrailEvent", "")
            or pool_id in ev.get("CloudTrailEvent", "")
        ]
    scanned = sum(len(raws) for raws in raw_by_operation.values())
    assert scanned >= 1, (
        f"no record for any of {_SECRET_BEARING_OPERATIONS!r} naming pool {pool_id!r} or client "
        f"{client_id!r} was found, so the byte-level absence scan covered nothing and would pass "
        f"for free. Per-operation counts: "
        f"{ {k: len(v) for k, v in raw_by_operation.items()} !r}"
    )
    for operation, raws in raw_by_operation.items():
        for raw in raws:
            assert password_token not in raw, (
                f"the plaintext password's run-unique token {password_token!r} appears in the "
                f"delivered CloudTrail record for {operation}. A credential this check sent to "
                f"Cognito seconds ago is now in an audit log. This is the highest-severity "
                f"divergence available in this service: customers' retention and access posture "
                f"for CloudTrail assumes it never carries secrets"
            )
            for secret in secrets:
                assert secret not in raw, (
                    f"a token InitiateAuth returned (length {len(secret)}, prefix "
                    f"{secret[:12]!r}) appears in the delivered CloudTrail record for "
                    f"{operation}; the credentials a successful authentication minted must not be "
                    f"logged either"
                )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
