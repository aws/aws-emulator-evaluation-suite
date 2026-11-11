"""aws-managed-key-reference-catalogue."""
from __future__ import annotations

import fnmatch
import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "aws-managed-key-reference-catalogue"
GROUP = 'key_metadata'
SERVICES = ['kms']

MANAGED_PREFIX = "alias/aws/"
MAX_PAGES = 50          # bounded pagination; ListAliases pages at 50-100 aliases each
MAX_DESCRIBED = 8       # cap the DescribeKey fan-out; the catalogue can be large
# A key id that is a syntactically valid UUID but names nothing.
ABSENT_KEY_ID = "00000000-1111-2222-3333-444444444444"

# This check creates NOTHING, so it needs no _teardown_key and no ctx.on_cleanup.


def _err(fn):
    """Return (Code, HTTPStatusCode, Message) of the ClientError fn() raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _allow_actions(policy_doc: str) -> list:
    """Every Action pattern appearing in an Effect=Allow statement of a key policy."""
    out = []
    for statement in json.loads(policy_doc).get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue
        action = statement.get("Action", [])
        out.extend([action] if isinstance(action, str) else list(action))
    return out


def _policy_allows(actions: list, operation: str) -> bool:
    """True if any Allow Action pattern in the policy covers `operation` (IAM `*` globbing)."""
    return any(fnmatch.fnmatchcase(operation, pattern) for pattern in actions)


def _list_all_aliases(kms, **kwargs) -> list:
    """Fully paginate ListAliases with a bounded page count, asserting Marker discipline."""
    out, marker, pages = [], None, 0
    while pages < MAX_PAGES:
        pages += 1
        page = kms.list_aliases(**({"Marker": marker} if marker else {}), **kwargs)
        out.extend(page.get("Aliases", []))
        truncated = page.get("Truncated", False)
        marker = page.get("NextMarker")
        if truncated:
            assert marker, f"Truncated=True must be accompanied by NextMarker; got {page.keys()}"
        else:
            assert "NextMarker" not in page, (
                f"Truncated=False must NOT return a NextMarker; got {page.get('NextMarker')!r}"
            )
            return out
    raise AssertionError(f"ListAliases did not terminate within {MAX_PAGES} pages")


@tags("axis:happy-path", "cap:c5", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The AWS-managed key catalogue is real reference data: `alias/aws/*` aliases exist unprompted.

    They resolve to keys whose `KeyManager` is `AWS`, and the alias listing's pagination and KeyId
    filter are exact, because every default-encryption path resolves an `alias/aws/<service>` first.
    """
    kms = ctx.client("kms")

    aliases = _list_all_aliases(kms)
    managed = [a for a in aliases if a.get("AliasName", "").startswith(MANAGED_PREFIX)]
    assert managed, (
        f"no {MANAGED_PREFIX}* aliases in ListAliases ({len(aliases)} aliases total) — the "
        f"AWS-managed key catalogue is reference data every account has; an emulator that "
        f"knows only customer-created keys fails here"
    )

    # Alias names are unique per account: pagination must not duplicate or drop entries.
    names = [a["AliasName"] for a in aliases]
    assert len(names) == len(set(names)), (
        f"ListAliases returned duplicate alias names across pages: "
        f"{sorted(n for n in set(names) if names.count(n) > 1)}"
    )

    account = None
    described = 0
    for alias in sorted(managed, key=lambda a: a["AliasName"]):
        name = alias["AliasName"]
        # AliasArn is structural, not volatile in shape: it must name this alias.
        arn = alias.get("AliasArn")
        assert arn and arn.endswith(f":{name}"), f"{name}: AliasArn {arn!r}"
        parts = arn.split(":")
        assert parts[2] == "kms", arn
        assert parts[3] == ctx.region, f"{name}: alias ARN region {parts[3]!r} != {ctx.region!r}"
        account = account or parts[4]
        assert parts[4] == account, f"{name}: alias ARN account {parts[4]!r} != {account!r}"

        # AWS lists predefined alias/aws/* aliases with no TargetKeyId until the backing
        # managed key is created. Those are skipped here and the assertion below still requires
        # at least one real managed key.
        target = alias.get("TargetKeyId")
        if not target or described >= MAX_DESCRIBED:
            continue
        described += 1

        meta = kms.describe_key(KeyId=target)["KeyMetadata"]
        assert meta["KeyManager"] == "AWS", (
            f"{name} -> {target}: KeyManager must be 'AWS', got {meta['KeyManager']!r}"
        )
        assert meta["KeyId"] == target, f"{name}: DescribeKey echoed {meta['KeyId']!r}"
        assert meta["KeyState"] == "Enabled", f"{name}: KeyState {meta['KeyState']!r}"
        assert meta["Enabled"] is True, f"{name}: {meta!r}"
        assert meta["Origin"] == "AWS_KMS", f"{name}: Origin {meta['Origin']!r}"
        assert meta["KeyUsage"] == "ENCRYPT_DECRYPT", f"{name}: KeyUsage {meta['KeyUsage']!r}"
        assert meta["AWSAccountId"] == account, (
            f"{name}: AWSAccountId {meta['AWSAccountId']!r} != alias ARN account {account!r}"
        )
        assert meta["Arn"].endswith(f":key/{target}"), f"{name}: key ARN {meta['Arn']!r}"

        # Resolving the alias NAME must return the same key as resolving the target id.
        by_alias = kms.describe_key(KeyId=name)["KeyMetadata"]
        assert by_alias["Arn"] == meta["Arn"], (
            f"{name}: DescribeKey by alias returned {by_alias['Arn']!r}, "
            f"by id returned {meta['Arn']!r}"
        )

        # The KeyId filter must return exactly the aliases pointing at that key, no more.
        filtered = _list_all_aliases(kms, KeyId=target)
        assert filtered, f"{name}: ListAliases(KeyId={target}) returned nothing"
        assert {a["AliasName"] for a in filtered} <= set(names), filtered
        assert all(a.get("TargetKeyId") == target for a in filtered), filtered
        assert name in {a["AliasName"] for a in filtered}, filtered

        # AWS-managed keys are rotated by AWS -- but whether the ACCOUNT may READ that is decided
        # by the key's AWS-authored key policy, and those policies differ per service.
        #
        # The AWS-authored policies differ by service, for example:
        #   alias/aws/elasticfilesystem, alias/aws/kafka -- policy carries an unconditional
        #     "Allow direct access to key metadata to the account" statement whose Action list
        #     includes kms:Get* -> GetKeyRotationStatus returns 200.
        #   alias/aws/acm -- policy grants the owner only kms:DescribeKey, kms:ListGrants,
        #     kms:RevokeGrant, kms:GetKeyPolicy -> GetKeyRotationStatus is
        #     AccessDeniedException/400 "...not authorized to perform: kms:GetKeyRotationStatus
        #     on resource: <key arn> because no resource-based policy allows...".
        #
        # So whether the call is even ALLOWED is derived from the key's own policy, and that is
        # what is asserted. An emulator that ships the managed-key catalogue without shipping the
        # per-service policies cannot satisfy both branches.
        #
        # AWS enables automatic rotation of a new managed key asynchronously after creation; until
        # it does, GetKeyRotationStatus returns KeyRotationEnabled=False with no
        # RotationPeriodInDays and no NextRotationDate. Afterwards it returns
        # True/365/CreationDate+365d. Both states are accepted -- an emulator that ships True
        # unconditionally, or that fills in a period/date while still reporting False, diverges
        # from real AWS.
        policy = kms.get_key_policy(KeyId=target, PolicyName="default")["Policy"]
        actions = _allow_actions(policy)
        may_read_rotation = _policy_allows(actions, "kms:GetKeyRotationStatus")

        if may_read_rotation:
            # The key policy Allows kms:GetKeyRotationStatus, so the call must succeed.
            rot = kms.get_key_rotation_status(KeyId=target)
            assert rot["KeyId"] == meta["Arn"], (
                f"{name}: GetKeyRotationStatus echoed KeyId {rot.get('KeyId')!r}, "
                f"expected the key ARN {meta['Arn']!r}"
            )
            if rot["KeyRotationEnabled"] is True:
                assert rot["RotationPeriodInDays"] == 365, (
                    f"{name}: AWS rotates a managed key on a 365-day period, got "
                    f"{rot.get('RotationPeriodInDays')!r}"
                )
                assert rot["NextRotationDate"] > meta["CreationDate"], (
                    f"{name}: NextRotationDate {rot.get('NextRotationDate')!r} must be after the "
                    f"key's CreationDate {meta.get('CreationDate')!r}"
                )
            else:
                assert rot["KeyRotationEnabled"] is False, (
                    f"{name}: KeyRotationEnabled must be a bool, got {rot['KeyRotationEnabled']!r}"
                )
                assert rot.get("RotationPeriodInDays") is None, (
                    f"{name}: a not-yet-enabled managed key must not carry a RotationPeriodInDays, "
                    f"got {rot.get('RotationPeriodInDays')!r}"
                )
                assert rot.get("NextRotationDate") is None, (
                    f"{name}: a not-yet-enabled managed key must not carry a NextRotationDate, "
                    f"got {rot.get('NextRotationDate')!r}"
                )
        else:
            # The key policy does NOT Allow kms:GetKeyRotationStatus, so the call is refused.
            rot_err = _err(lambda _t=target: kms.get_key_rotation_status(KeyId=_t))
            rot_code, rot_status, rot_msg = rot_err
            assert rot_code == "AccessDeniedException", (
                f"{name}: an unauthorised GetKeyRotationStatus must be AccessDeniedException, "
                f"got {rot_code!r} (HTTP {rot_status})"
            )
            assert rot_status == 400, f"{name}: expected HTTP 400, got {rot_status}"
            assert "kms:GetKeyRotationStatus" in rot_msg and meta["Arn"] in rot_msg, (
                f"{name}: the denial must name the action and the key ARN, not be a bare "
                f"AccessDenied: {rot_msg!r}"
            )
            # The message opens with the caller's ARN, which the check never reads.
            rot_tail = (
                f" is not authorized to perform: kms:GetKeyRotationStatus on resource: "
                f"{meta['Arn']} because no resource-based policy allows the "
                f"kms:GetKeyRotationStatus action"
            )
            assert rot_msg.startswith("User: arn:") and rot_msg.endswith(rot_tail), (
                f"{name}: expected 'User: <caller arn>{rot_tail}', got {rot_msg!r}"
            )

    assert described > 0, (
        f"{len(managed)} {MANAGED_PREFIX}* aliases were listed but none carried a TargetKeyId, "
        f"so no AWS-managed key could be described — either the account has never used an "
        f"AWS-managed key, or the emulator publishes alias names with no backing reference data"
    )

    # --- Negative: an AWS-managed key is not aliasable, and the ORDER of validation is fixed.
    #
    # Observed on AWS: the refusal is NOT the alias-name reservation (NotAuthorizedException,
    # "Aliases beginning with alias/aws/ are reserved") -- the alias name is never reached,
    # because CreateAlias resolves the TARGET first and then evaluates the target key's policy:
    #   AliasName=alias/aws/<new>,  TargetKeyId=<a real AWS-managed key>
    #     -> AccessDeniedException/400 "...not authorized to perform: kms:CreateAlias on
    #        resource: <key arn> because no resource-based policy allows..."   (key policy)
    #   AliasName=alias/aws/<new>,  TargetKeyId=<absent uuid>
    #     -> NotFoundException/400 "Key '<key arn>' does not exist"            (target first)
    #   AliasName=alias/<new>,      TargetKeyId=<absent uuid>
    #     -> NotFoundException/400, IDENTICAL -- so the reserved prefix contributes nothing
    #        once the target cannot be resolved.
    # Both facts are asserted. The pair is the discriminating one: an emulator that validates
    # the alias NAME before the target answers the reserved-prefix error to the second case,
    # where real KMS answers NotFoundException.
    target_managed = sorted(
        (a for a in managed if a.get("TargetKeyId")), key=lambda a: a["AliasName"]
    )[0]["TargetKeyId"]
    reserved_alias = f"{MANAGED_PREFIX}sim2real-behav-not-allowed"
    denied = _err(
        lambda: kms.create_alias(AliasName=reserved_alias, TargetKeyId=target_managed)
    )
    denied_code, denied_status, denied_msg = denied
    assert denied_code == "AccessDeniedException", (
        f"CreateAlias on an AWS-managed key must raise AccessDeniedException (the key's own "
        f"policy grants the account no kms:CreateAlias), got {denied_code!r} "
        f"(HTTP {denied_status})"
    )
    assert denied_status == 400, f"expected HTTP 400, got {denied_status}"
    assert "kms:CreateAlias" in denied_msg, (
        f"the denial must name kms:CreateAlias, so it is the key policy talking and not a "
        f"generic refusal: {denied_msg!r}"
    )
    denied_tail = (
        f" is not authorized to perform: kms:CreateAlias on resource: "
        f"arn:aws:kms:{ctx.region}:{account}:key/{target_managed} because no resource-based "
        f"policy allows the kms:CreateAlias action"
    )
    assert denied_msg.startswith("User: arn:") and denied_msg.endswith(denied_tail), (
        f"expected 'User: <caller arn>{denied_tail}', got {denied_msg!r}"
    )

    # Target resolution precedes alias-name evaluation, under BOTH prefixes.
    for label, alias_name in (
        ("reserved prefix", reserved_alias),
        ("ordinary prefix", "alias/sim2real-behav-absent-target"),
    ):
        absent = _err(
            lambda _n=alias_name: kms.create_alias(
                AliasName=_n, TargetKeyId=ABSENT_KEY_ID
            )
        )
        absent_code, absent_status, absent_msg = absent
        assert absent_code == "NotFoundException", (
            f"{label}: CreateAlias with an unresolvable TargetKeyId must raise "
            f"NotFoundException -- the target is resolved BEFORE the alias name is judged -- "
            f"got {absent_code!r} (HTTP {absent_status})"
        )
        assert absent_status == 400, f"{label}: expected HTTP 400, got {absent_status}"
        assert ABSENT_KEY_ID in absent_msg, (
            f"{label}: the NotFound must name the unresolvable key: {absent_msg!r}"
        )
        expected = f"Key 'arn:aws:kms:{ctx.region}:{account}:key/{ABSENT_KEY_ID}' does not exist"
        assert absent_msg == expected, f"{label}: expected message {expected!r}, got {absent_msg!r}"

    # --- Effect absent: the refusal created nothing, and the catalogue is unchanged.
    after = {a["AliasName"] for a in _list_all_aliases(kms)}
    assert f"{MANAGED_PREFIX}sim2real-behav-not-allowed" not in after, (
        "the refused CreateAlias must not appear in the catalogue"
    )
    assert after >= {a["AliasName"] for a in managed}, (
        "the AWS-managed catalogue must be unchanged by a refused CreateAlias"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
