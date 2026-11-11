"""client-token-is-validated-on-every-mutating-operation-rejected."""
from __future__ import annotations

import json
from urllib.parse import urlencode

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "client-token-is-validated-on-every-mutating-operation-rejected"
GROUP = 'directory-data-rejected'
SERVICES = ['ds-data']

# The nine ds-data operations carrying an @idempotencyToken ClientToken -- every mutating one, and
# only the mutating ones. The eight read operations have no such member at all.
_MUTATING = (
    ("create_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("update_user", {"SAMAccountName": "sim2real-behav-u", "GivenName": "Sim"}),
    ("disable_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("delete_user", {"SAMAccountName": "sim2real-behav-u"}),
    ("create_group", {"SAMAccountName": "sim2real-behav-g"}),
    ("update_group", {"SAMAccountName": "sim2real-behav-g", "GroupScope": "Global"}),
    ("delete_group", {"SAMAccountName": "sim2real-behav-g"}),
    ("add_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"}),
    ("remove_group_member", {"GroupName": "sim2real-behav-g", "MemberName": "sim2real-behav-u"}),
)

# (SDK method name, PascalCase operation name for the raw wire call, kwargs beyond DirectoryId).
_READ_ONLY = (
    ("list_users", "ListUsers", {}),
    ("list_groups", "ListGroups", {}),
    ("describe_user", "DescribeUser", {"SAMAccountName": "sim2real-behav-u"}),
    ("describe_group", "DescribeGroup", {"SAMAccountName": "sim2real-behav-g"}),
    ("search_users", "SearchUsers", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}),
    ("search_groups", "SearchGroups", {"SearchString": "sim2real", "SearchAttributes": ["Cn"]}),
    ("list_group_members", "ListGroupMembers", {"SAMAccountName": "sim2real-behav-g"}),
    ("list_groups_for_member", "ListGroupsForMember", {"SAMAccountName": "sim2real-behav-u"}),
)

# ClientToken is length 1..128 with pattern ^[\x00-\x7F]+$ -- ASCII only, which is unusual enough
# that a generated emulator is unlikely to enforce it.
_NON_ASCII_TOKEN = "sim2real-tokén"


# ===== helpers =====
def _refusal(fn):
    """Call fn(); return (Code, Message, Reason) of the ClientError it must raise.

    Raises on SUCCESS rather than returning a falsy sentinel, so an emulator accepting a token real
    AWS refuses cannot read as a code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {}) or {}
        return error.get("Code"), error.get("Message") or "", exc.response.get("Reason")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {result!r}")


def _raw_call(client, region, op_name, params, extra_body=None):
    """Serialize `params` through botocore's own request builder, splice `extra_body` fields into
    the resulting JSON body, then sign and send the request directly over the wire -- bypassing
    the SDK's client-side shape check so the SERVER's handling of an undeclared member is what
    gets observed, rather than botocore's refusal to send it in the first place.
    """
    import urllib3

    op = client.meta.service_model.operation_model(op_name)
    request = client._serializer.serialize_to_request(dict(params), op)
    body = json.loads(request["body"]) if request["body"] else {}
    body.update(extra_body or {})
    data = json.dumps(body).encode()
    url = client.meta.endpoint_url + request["url_path"]
    if request["query_string"]:
        url = f"{url}?{urlencode(request['query_string'])}"
    creds = client._request_signer._credentials
    frozen = creds.get_frozen_credentials() if hasattr(creds, "get_frozen_credentials") else creds
    req = AWSRequest(method="POST", url=url, data=data, headers={"content-type": "application/json"})
    SigV4Auth(frozen, "ds-data", region).add_auth(req)
    resp = urllib3.PoolManager().request(
        "POST", url, body=data, headers=dict(req.headers.items()), retries=False
    )
    return resp.status, (json.loads(resp.data) if resp.data else {})


def _absent_directory_id(ds) -> str:
    """A DirectoryId matching ^d-[0-9a-f]{10}$ that this account demonstrably does not hold."""
    owned = set()
    token = None
    while True:
        page = ds.describe_directories(**({"NextToken": token} if token else {}))
        for description in page.get("DirectoryDescriptions") or []:
            owned.add(description.get("DirectoryId"))
        token = page.get("NextToken")
        if not token:
            break
    for candidate in (f"d-{n:010x}" for n in range(0x5E9207CBA4, 0x5E9207CBA4 + 64)):
        if candidate not in owned:
            return candidate
    raise AssertionError(f"could not find an unissued DirectoryId; owned={sorted(owned)}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """All nine ds-data mutating operations validate ClientToken identically and before
    authorization (ASCII-only pattern, 128-character bound) and echo its value in the refusal, while
    the eight read operations carry no such member."""
    ds = ctx.client("ds")
    dsd = ctx.client("ds-data")
    absent = _absent_directory_id(ds)

    pattern_refusals = {}
    length_refusals = {}
    accepted = {}
    for operation, kwargs in _MUTATING:
        call = getattr(dsd, operation)
        pattern_refusals[operation] = _refusal(
            lambda c=call, k=kwargs: c(DirectoryId=absent, ClientToken=_NON_ASCII_TOKEN, **k)
        )
        length_refusals[operation] = _refusal(
            lambda c=call, k=kwargs: c(DirectoryId=absent, ClientToken="t" * 129, **k)
        )
        accepted[operation] = _refusal(
            lambda c=call, k=kwargs: c(
                DirectoryId=absent, ClientToken="sim2real-behav-client-token-01", **k
            )
        )

    assert len(pattern_refusals) == 9, (
        f"all nine @idempotencyToken-bearing operations must be exercised, got "
        f"{sorted(pattern_refusals)}"
    )

    for operation in sorted(pattern_refusals):
        code, message, reason = pattern_refusals[operation]
        assert code == "ValidationException", (
            f"ds-data {operation} must refuse a non-ASCII ClientToken, got {code!r} (None means the "
            f"pattern is not enforced on this operation, which is the asymmetry this check exists "
            f"to catch)"
        )
        assert reason is None, f"a constraint refusal carries no Reason, got {reason!r}"
        assert message == (
            f"1 validation error detected: Value '{_NON_ASCII_TOKEN}' at 'clientToken' failed to "
            f"satisfy constraint: Member must satisfy regular expression pattern: [\\x00-\\x7F]+"
        ), (
            f"ds-data {operation} must name clientToken and quote the ASCII-only pattern, and must "
            f"ECHO the token (it is not @sensitive), got {message!r}"
        )

        code, message, reason = length_refusals[operation]
        assert code == "ValidationException", (
            f"ds-data {operation} must refuse a 129-character ClientToken, got {code!r}"
        )
        assert message == (
            f"1 validation error detected: Value '{'t' * 129}' at 'clientToken' failed to satisfy "
            f"constraint: Member must have length less than or equal to 128"
        ), (
            f"ds-data {operation} must name clientToken's length bound of 128, got {message!r}"
        )

        # POSITIVE CONTROL, per operation: a legal token passes validation and the request is
        # refused one layer later. Without this, a service refusing every ClientToken would pass.
        code, message, reason = accepted[operation]
        assert code == "AccessDeniedException", (
            f"ds-data {operation} with a legal ASCII ClientToken must pass validation and reach "
            f"authorization, got {code!r} -- a ValidationException here means the token is refused "
            f"outright rather than validated"
        )
        assert reason == "IAM_AUTH", (
            f"{operation} must be refused by authorization once the token is accepted, got Reason "
            f"{reason!r}"
        )
        assert "clientToken" not in message, (
            f"an accepted token must not appear in the authorization refusal, got {message!r}"
        )

    # THE UNIFORMITY CLAIM: one message per fault class, across all nine.
    assert len(set(pattern_refusals.values())) == 1, (
        f"the ASCII pattern must be enforced identically on all nine mutating operations, got "
        f"{pattern_refusals!r}"
    )
    assert len(set(length_refusals.values())) == 1, (
        f"the length bound must be enforced identically on all nine mutating operations, got "
        f"{length_refusals!r}"
    )
    assert len(set(accepted.values())) == 1, (
        f"once the token is legal all nine must be refused identically by authorization, got "
        f"{accepted!r}"
    )
    assert set(pattern_refusals.values()).isdisjoint(set(length_refusals.values())), (
        "a pattern fault and a length fault must not produce one message"
    )

    # --- The other half of the asymmetry: the eight read operations have no ClientToken member.
    # Whether botocore refuses to SEND one is a fact about the SDK's packaged model, not about the
    # SERVICE: the exact same model ships against every target regardless of endpoint, so a
    # client-side-only check is incapable of ever failing -- the request never reaches the wire.
    # Instead, splice the SAME non-ASCII token every mutating operation refuses with a
    # ValidationException directly into the wire body -- bypassing the SDK's shape check entirely
    # -- and confirm the SERVICE, not just the SDK, never applies that constraint to a read
    # operation.
    for operation, op_name, kwargs in _READ_ONLY:
        params = dict(DirectoryId=absent, **kwargs)
        status_plain, body_plain = _raw_call(dsd, dsd.meta.region_name, op_name, params)
        status_token, body_token = _raw_call(
            dsd, dsd.meta.region_name, op_name, params, {"ClientToken": _NON_ASCII_TOKEN}
        )
        assert status_plain == 403, (
            f"ds-data {op_name} against an unreachable directory must be refused by authorization "
            f"(403) on the raw wire call, got {status_plain} {body_plain!r} -- the wire plumbing "
            f"itself is suspect if this fails"
        )
        assert (status_token, body_token) == (status_plain, body_plain), (
            f"ds-data {op_name} answered differently when the wire body carried the SAME "
            f"non-ASCII ClientToken every mutating operation refuses with a ValidationException -- "
            f"got {(status_token, body_token)!r} vs {(status_plain, body_plain)!r} -- a read "
            f"operation must not apply a constraint its shape does not declare, even when handed a "
            f"value the constraint layer elsewhere refuses"
        )

    # --- POSITIVE CONTROL: the ds control plane is healthy, and it has no ClientToken anywhere --
    # so this whole member class is ds-data's alone.
    limits = ds.get_directory_limits()
    assert isinstance(limits.get("DirectoryLimits"), dict), (
        f"ds GetDirectoryLimits must still succeed, got {limits!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
