"""a-kms-encrypted-repository-is-audited-as-ecr-acting-on-the-callers-behalf."""

# A KMS-encrypted repository makes ECR call KMS on the caller's behalf; CloudTrail records those
# calls as the caller's identity with userIdentity.invokedBy "ecr.amazonaws.com", ECR takes a grant
# on the key, and deleting the repository retires that grant. The key is left pending deletion.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-kms-encrypted-repository-is-audited-as-ecr-acting-on-the-callers-behalf"
GROUP = "eventing"
SERVICES = ["cloudtrail", "ecr", "kms"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_ECR_EVENT_SOURCE = "ecr.amazonaws.com"  # the Smithy model's cloudTrailEventSource
_KMS_EVENT_SOURCE = "kms.amazonaws.com"
# The subset ECR must hold to encrypt and decrypt repository content; the full operation set is
# not documented, so this is a subset assertion.
_REQUIRED_GRANT_OPERATIONS = {"Decrypt", "GenerateDataKey"}

_INDEX_BUDGET_S = 255.0
_GRANT_BUDGET_S = 300.0
_POLL_INTERVAL_S = 2.0
_PAGE_CEILING = 40
_PENDING_DELETION_DAYS = 7

# ===== helpers =====


def _lookup_all(ct, **kw):
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
    raise AssertionError(
        f"{DATAPLANE_MARKER}: LookupEvents paged past {_PAGE_CEILING} pages without exhausting"
    )


def _records(ct, event_name, since):
    """The event's records since the run began; an unbounded window pages a busy account forever."""
    return [
        json.loads(e["CloudTrailEvent"])
        for e in _lookup_all(
            ct,
            LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
            StartTime=since,
        )
    ]


def _await(ct, event_name, predicate, why, since, budget_s=_INDEX_BUDGET_S):
    deadline = time.monotonic() + budget_s
    examined = 0
    while True:
        found = _records(ct, event_name, since)
        examined = len(found)
        for rec in found:
            if predicate(rec):
                return rec
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no {event_name} record satisfying {why} within "
                f"{budget_s:.0f}s; expected 1, actual 0 of {examined} examined"
            )
        time.sleep(_POLL_INTERVAL_S)


def _create_cmk(ctx, account_id):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=f"{CHECK} repository CMK",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(
            KeyId=key_id, PendingWindowInDays=_PENDING_DELETION_DAYS
        )
    )
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "simparity-ecr-cmk",
                "Statement": [
                    {
                        "Sid": "EnableRoot",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowEcr",
                        "Effect": "Allow",
                        "Principal": {"Service": "ecr.amazonaws.com"},
                        "Action": [
                            "kms:Decrypt",
                            "kms:GenerateDataKey",
                            "kms:GenerateDataKeyWithoutPlaintext",
                            "kms:DescribeKey",
                            "kms:CreateGrant",
                            "kms:RetireGrant",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    return key_id, key["Arn"]


def _list_grants(kms, key_id):
    grants = []
    marker = None
    for _ in range(_PAGE_CEILING):
        kw = {"KeyId": key_id, "Limit": 100}
        if marker:
            kw["Marker"] = marker
        page = kms.list_grants(**kw)
        grants.extend(page.get("Grants", []))
        if not page.get("Truncated"):
            return grants
        marker = page.get("NextMarker")
    raise AssertionError(
        f"ListGrants paged past {_PAGE_CEILING} pages for key {key_id} without exhausting"
    )


def _ecr_grants(grants):
    return [
        g
        for g in grants
        if "ecr" in (g.get("GranteePrincipal") or "").lower()
        or "ecr" in (g.get("Name") or "").lower()
    ]


def _delete_repository_quietly(ecr, name):
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:eventing",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A KMS-encrypted ECR repository is audited as the caller's CreateRepository and as ECR's own
    KMS calls marked invokedBy ecr.amazonaws.com; ECR's grant on the key is retired on delete.
    """
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    kms = ctx.client("kms")
    ecr = ctx.client("ecr")
    ct = ctx.client("cloudtrail")

    key_id, key_arn = _create_cmk(ctx, account_id)

    # Grants BEFORE the repository exists -- the baseline that makes leg 3 a real change and not a
    # pre-existing condition.
    before = _ecr_grants(_list_grants(kms, key_id))
    assert before == [], (
        "a freshly created CMK must carry no ECR grant, otherwise leg 3 proves nothing: expected 0 "
        f"ECR grants, actual {len(before)} ({before!r})"
    )

    repo_name = ctx.unique_name("simparity-ct-ecr-")
    created = ecr.create_repository(
        repositoryName=repo_name,
        encryptionConfiguration={"encryptionType": "KMS", "kmsKey": key_arn},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )["repository"]
    ctx.on_cleanup(lambda: _delete_repository_quietly(ecr, repo_name))
    assert created["encryptionConfiguration"]["encryptionType"] == "KMS", (
        "the repository must really be KMS-encrypted, otherwise ECR has no reason to call KMS: "
        f"expected 'KMS', actual {created['encryptionConfiguration']['encryptionType']!r}"
    )
    assert created["encryptionConfiguration"]["kmsKey"] == key_arn, (
        f"the repository's kmsKey: expected {key_arn!r}, actual "
        f"{created['encryptionConfiguration']['kmsKey']!r}"
    )

    # ---- leg 3: the grant ECR took ----------------------------------------------------------------
    deadline = time.monotonic() + _GRANT_BUDGET_S
    grants = []
    while True:
        grants = _ecr_grants(_list_grants(kms, key_id))
        if grants:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: ECR must take a KMS grant on the CMK backing a KMS-encrypted "
                f"repository: expected >=1 ECR grant on {key_id} within {_GRANT_BUDGET_S:.0f}s, "
                f"actual 0 of {len(_list_grants(kms, key_id))} grants total"
            )
        time.sleep(_POLL_INTERVAL_S)
    grant = grants[0]
    operations = set(grant.get("Operations") or [])
    missing = _REQUIRED_GRANT_OPERATIONS - operations
    assert not missing, (
        "ECR's grant must let it both wrap and unwrap repository data keys: expected at least "
        f"{sorted(_REQUIRED_GRANT_OPERATIONS)} among the grant's operations, actual missing "
        f"{sorted(missing)}; full observed set {sorted(operations)}"
    )
    grant_id = grant["GrantId"]

    # ---- leg 1: the caller's OWN record, the twin control for attribution --------------------------
    create_record = _await(
        ct,
        "CreateRepository",
        lambda r: repo_name in json.dumps(r.get("requestParameters") or {}),
        f"a CreateRepository record naming {repo_name}",
        since,
    )
    assert create_record.get("eventSource") == _ECR_EVENT_SOURCE, (
        f"eventSource: expected {_ECR_EVENT_SOURCE!r}, actual "
        f"{create_record.get('eventSource')!r}"
    )
    caller_ident = create_record.get("userIdentity") or {}
    assert caller_ident.get("arn") == caller_arn, (
        "the caller's own call must be attributed to the caller: expected "
        f"{caller_arn!r}, actual {caller_ident.get('arn')!r}"
    )
    assert caller_ident.get("type") != "AWSService", (
        "the caller's own call must NOT be attributed to a service principal -- this is the twin "
        f"control for leg 2: expected anything but 'AWSService', actual {caller_ident.get('type')!r}"
    )
    assert "invokedBy" not in caller_ident, (
        "a call the caller made directly must carry no invokedBy: expected the key absent, actual "
        f"{caller_ident.get('invokedBy')!r}; stamping invokedBy on every record fails here"
    )
    assert key_arn in json.dumps(create_record.get("requestParameters") or {}), (
        "the CreateRepository record must name the CMK the caller chose: expected "
        f"{key_arn!r} inside "
        f"{json.dumps(create_record.get('requestParameters') or {})[:200]!r}, actual absent"
    )

    # ---- leg 2: the records for calls the caller never made ----------------------------------------
    def _is_ecr_kms_call(rec):
        if rec.get("eventSource") != _KMS_EVENT_SOURCE:
            return False
        if key_id not in json.dumps(rec) and key_arn not in json.dumps(rec):
            return False
        return (rec.get("userIdentity") or {}).get("invokedBy") == _ECR_EVENT_SOURCE

    service_record = None
    deadline = time.monotonic() + _INDEX_BUDGET_S
    while True:
        candidates = []
        for event_name in ("CreateGrant", "GenerateDataKey", "DescribeKey"):
            candidates.extend(_records(ct, event_name, since))
        matches = [r for r in candidates if _is_ecr_kms_call(r)]
        if matches:
            service_record = matches[0]
            break
        if time.monotonic() >= deadline:
            near = [
                (r.get("eventName"), (r.get("userIdentity") or {}).get("type"),
                 (r.get("userIdentity") or {}).get("invokedBy"))
                for r in candidates
                if key_id in json.dumps(r) or key_arn in json.dumps(r)
            ]
            raise AssertionError(
                f"{DATAPLANE_MARKER}: ECR's own KMS calls for key {key_id} were not audited with "
                f"invokedBy {_ECR_EVENT_SOURCE!r} within {_INDEX_BUDGET_S:.0f}s; expected >=1, "
                f"actual 0. Records naming the key, as (eventName, userIdentity.type, invokedBy): "
                f"{near[:6]!r}"
            )
        time.sleep(_POLL_INTERVAL_S)

    svc_ident = service_record.get("userIdentity") or {}
    # AWS attributes a call a service makes on the caller's behalf to the CALLER, and marks the
    # service in invokedBy (CloudTrail userIdentity element, "invokedBy").
    assert svc_ident.get("type") == caller_ident.get("type"), (
        "a KMS call ECR made on the caller's behalf is attributed to the caller's identity: "
        f"expected userIdentity.type {caller_ident.get('type')!r}, actual "
        f"{svc_ident.get('type')!r}"
    )
    assert svc_ident.get("invokedBy") == _ECR_EVENT_SOURCE, (
        f"userIdentity.invokedBy: expected {_ECR_EVENT_SOURCE!r}, actual "
        f"{svc_ident.get('invokedBy')!r}"
    )
    assert svc_ident.get("arn") == caller_arn, (
        "the record of a call ECR made on the caller's behalf carries the caller's ARN: expected "
        f"{caller_arn!r}, actual {svc_ident.get('arn')!r}"
    )
    assert service_record.get("errorCode") is None, (
        "ECR's own KMS call must have succeeded, or the repository would not be usable: expected no "
        f"errorCode, actual {service_record.get('errorCode')!r}"
    )
    assert service_record.get("eventID") != create_record.get("eventID"), (
        "the caller's CreateRepository and ECR's KMS call must be two distinct records: expected "
        f"different eventIDs, actual both {create_record.get('eventID')!r}"
    )
    assert "plaintext" not in json.dumps(service_record).lower(), (
        "a KMS record must never carry key material: expected no 'plaintext' anywhere in the "
        "record, actual present"
    )

    # ---- leg 4: deleting the repository retires the grant ------------------------------------------
    ecr.delete_repository(repositoryName=repo_name, force=True)
    # Prove gone AND unusable, via a read that must now fail with the specific not-found code.
    try:
        still = ecr.describe_repositories(repositoryNames=[repo_name])
        raise AssertionError(
            "DescribeRepositories must no longer find the deleted repository: expected "
            f"RepositoryNotFoundException, actual {still.get('repositories')!r}"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "RepositoryNotFoundException", (
            "a deleted repository must be unusable with the specific not-found code: expected "
            f"'RepositoryNotFoundException', actual {code!r}"
        )
        assert message == f"The repository with name '{created['repositoryName']}' does not exist in the registry with id '{ctx.account}'", (
            f"expected the exact RepositoryNotFoundException message AWS returns, got {message!r}"
        )
    deadline = time.monotonic() + _GRANT_BUDGET_S
    remaining = None
    while True:
        remaining = [g for g in _list_grants(kms, key_id) if g["GrantId"] == grant_id]
        if not remaining:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the grant ECR took ({grant_id}) must be retired once the repository is deleted, "
                f"or the key stays usable by a service after its resource is gone: expected 0 "
                f"grants with that id within {_GRANT_BUDGET_S:.0f}s, actual {len(remaining)} "
                f"({remaining!r})"
            )
        time.sleep(_POLL_INTERVAL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
