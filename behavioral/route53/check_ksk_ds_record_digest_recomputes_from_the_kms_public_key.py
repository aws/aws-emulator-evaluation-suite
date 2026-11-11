"""ksk-ds-record-digest-recomputes-from-the-kms-public-key."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ksk-ds-record-digest-recomputes-from-the-kms-public-key"
GROUP = "representation"
SERVICES = ["route53"]

_SUBJECT = "route53-ksk-ds-digest"

_MANAGED_TAGS = [{"Key": "sim2real", "Value": _SUBJECT},
                 {"Key": "sim2real:managed", "Value": "true"},
                 {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code") or ""


def _msg_of(exc):
    return exc.response.get("Error", {}).get("Message") or str(exc)


def _poll(probe, done, *, timeout_s, interval_s=2.0, what="condition"):
    """Poll an observable condition to a bounded deadline; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last={last!r}"
            )
        time.sleep(interval_s)


def _caller_reference():
    return f"cr-{secrets.token_hex(16)}"

# Zone names use the RFC 2606 reserved `.test` TLD so no third party can register them.



def _zone_name(ctx, prefix="zone"):
    raw = ctx.unique_name("sim2real-behav-" + prefix).lower().replace("_", "-")
    return f"{raw}.example.test."


def _change(r53, zone_id, changes, tries=4):
    """Submit a ChangeBatch, retrying only the two documented transient conditions."""
    for attempt in range(tries):
        try:
            return r53.change_resource_record_sets(
                HostedZoneId=zone_id, ChangeBatch={"Changes": changes}
            )["ChangeInfo"]["Id"]
        except ClientError as exc:
            if _code_of(exc) not in ("PriorRequestNotComplete", "Throttling") \
                    or attempt == tries - 1:
                raise
            time.sleep(2.0 * (attempt + 1))


def _list_all(r53, zone_id, **extra):
    """Every record set in the zone, fully paginated."""
    out = []
    kwargs = {"HostedZoneId": zone_id}
    kwargs.update(extra)
    while True:
        resp = r53.list_resource_record_sets(**kwargs)
        out.extend(resp["ResourceRecordSets"])
        if not resp.get("IsTruncated"):
            return out
        kwargs["StartRecordName"] = resp["NextRecordName"]
        kwargs["StartRecordType"] = resp["NextRecordType"]
        if resp.get("NextRecordIdentifier"):
            kwargs["StartRecordIdentifier"] = resp["NextRecordIdentifier"]


def _at(rrsets, name, rtype):
    want = name.rstrip(".").lower()
    return [r for r in rrsets if r["Name"].rstrip(".").lower() == want and r["Type"] == rtype]


def _zone_gone(r53, zone_id):
    try:
        r53.get_hosted_zone(Id=zone_id)
        return False
    except ClientError as exc:
        return _code_of(exc) == "NoSuchHostedZone"


def _empty_and_delete_zone(r53, zone_id):
    def _non_apex():
        return [r for r in _list_all(r53, zone_id) if r["Type"] not in ("NS", "SOA")]

    leftovers = _non_apex()
    # Alias records first: an alias whose target is a record in the SAME zone blocks that
    # target's deletion.
    leftovers.sort(key=lambda r: 0 if r.get("AliasTarget") else 1)
    if leftovers:
        try:
            _change(r53, zone_id,
                    [{"Action": "DELETE", "ResourceRecordSet": r} for r in leftovers])
        except ClientError:
            for rrs in leftovers:  # one unbatchable set must not strand the rest
                try:
                    _change(r53, zone_id, [{"Action": "DELETE", "ResourceRecordSet": rrs}])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in (
                        "HostedZoneNotFound",
                        "NoSuchHealthCheck",
                        "NoSuchHostedZone",
                    ):
                        raise
    try:
        _poll(_non_apex, lambda rem: rem == [], timeout_s=60.0, interval_s=2.0,
              what=f"the non-apex record sets in {zone_id} to clear before DeleteHostedZone")
    except AssertionError:
        print(f"[route53-cleanup] LEAK: hosted zone {zone_id} still holds record sets and "
              f"cannot be deleted; it bills $0.50/month until removed by hand")
        raise
    r53.delete_hosted_zone(Id=zone_id)
    _poll(lambda: _zone_gone(r53, zone_id), lambda gone: gone,
          timeout_s=60.0, interval_s=2.0,
          what=f"GetHostedZone({zone_id}) to report NoSuchHostedZone after DeleteHostedZone")


def _create_zone(ctx, r53, prefix="zone"):
    """Create a tagged public hosted zone and register its teardown.

    Returns (zone id, zone name, the four delegated nameserver hostnames).
    """
    resp = r53.create_hosted_zone(
        Name=_zone_name(ctx, prefix),
        CallerReference=_caller_reference(),
        HostedZoneConfig={"Comment": "sim2real-behav test", "PrivateZone": False},
    )
    zone_id = resp["HostedZone"]["Id"]
    ctx.on_cleanup(lambda z=zone_id: _empty_and_delete_zone(r53, z))
    r53.change_tags_for_resource(
        ResourceType="hostedzone", ResourceId=zone_id.split("/")[-1], AddTags=_MANAGED_TAGS,
    )
    return zone_id, resp["HostedZone"]["Name"], resp["DelegationSet"]["NameServers"]


def _wait_insync(r53, change_id, timeout_s=180.0):
    """Poll GetChange to INSYNC, the only propagation barrier Route 53 publishes."""
    return _poll(
        lambda: r53.get_change(Id=change_id)["ChangeInfo"]["Status"],
        lambda st: st == "INSYNC",
        timeout_s=timeout_s, interval_s=2.0,
        what=f"change {change_id} to reach INSYNC",
    )

# Route 53 DNSSEC requires an ECC_NIST_P256 SIGN_VERIFY customer managed key in us-east-1,
# whatever the region under test.



def _dnssec_kms_key(ctx):
    """Create an ECC_NIST_P256 CMK with the documented Route 53 DNSSEC key policy.

    Returns (kms client, key arn).
    """
    kms = ctx.client("kms", region="us-east-1")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "EnableRootPermissions", "Effect": "Allow",
             "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "AllowRoute53DNSSECUse", "Effect": "Allow",
             "Principal": {"Service": "dnssec-route53.amazonaws.com"},
             "Action": ["kms:DescribeKey", "kms:GetPublicKey", "kms:Sign"], "Resource": "*",
             "Condition": {"StringEquals": {"aws:SourceAccount": account_id}}},
            {"Sid": "AllowRoute53DNSSECCreateGrant", "Effect": "Allow",
             "Principal": {"Service": "dnssec-route53.amazonaws.com"},
             "Action": "kms:CreateGrant", "Resource": "*",
             "Condition": {"Bool": {"kms:GrantIsForAWSResource": "true"}}},
        ],
    }
    key = kms.create_key(
        Description="sim2real-behav route53 DNSSEC KSK backing key",
        KeyUsage="SIGN_VERIFY",
        KeySpec="ECC_NIST_P256",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": t["Key"], "TagValue": t["Value"]} for t in _MANAGED_TAGS],
    )["KeyMetadata"]
    # 7 days is the shortest window KMS accepts; a CMK cannot be deleted immediately.
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(KeyId=key["Arn"], PendingWindowInDays=7))
    return kms, key["Arn"]


def _delete_ksk(r53, zone_id, ksk_name):
    """Deactivate then delete: DeleteKeySigningKey refuses an ACTIVE key."""
    try:
        r53.deactivate_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    except ClientError as exc:
        if _code_of(exc) not in ("NoSuchKeySigningKey", "InvalidKeySigningKeyStatus"):
            raise
    try:
        r53.delete_key_signing_key(HostedZoneId=zone_id, Name=ksk_name)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchKeySigningKey":
            raise


def _create_ksk(ctx, r53, zone_id, kms_arn):
    """Create an ACTIVE key-signing key on the zone; return (name, the KeySigningKey object).

    CreateKeySigningKey can refuse until the KMS key is usable, so it is retried on those codes.
    """
    name = ctx.unique_name("ksk_").replace("-", "_")
    deadline = time.monotonic() + 120
    while True:
        try:
            resp = r53.create_key_signing_key(
                CallerReference=_caller_reference(), HostedZoneId=zone_id,
                KeyManagementServiceArn=kms_arn, Name=name, Status="ACTIVE",
            )
            break
        except ClientError as exc:
            transient = _code_of(exc) in ("InvalidKMSArn", "ConcurrentModification",
                                          "InvalidKeySigningKeyStatus")
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_ksk(r53, zone_id, name))
    _wait_insync(r53, resp["ChangeInfo"]["Id"])
    return name, resp["KeySigningKey"]


# RFC 4034 recomputation in pure stdlib, from the KMS public key.



def _p256_raw_point(der_spki):
    """The 64 raw bytes X||Y of a P-256 public key, from its DER SubjectPublicKeyInfo.

    The uncompressed point 0x04||X||Y is the last 65 bytes; the 0x04 prefix is asserted.
    """
    assert len(der_spki) >= 65, (
        f"a P-256 SubjectPublicKeyInfo is at least 65 bytes, got {len(der_spki)}: "
        f"{der_spki.hex()}"
    )
    point = der_spki[-65:]
    assert point[0] == 0x04, (
        f"expected an UNCOMPRESSED EC point (leading 0x04) in the last 65 bytes of the DER "
        f"SubjectPublicKeyInfo, got a leading 0x{point[0]:02x}: {der_spki.hex()}"
    )
    return point[1:]


def _dnskey_rdata(flags, algorithm, key64):
    """DNSKEY RDATA per RFC 4034 section 2.1; the protocol field is always 3."""
    return struct.pack(">HBB", flags, 3, algorithm) + key64


def _key_tag(rdata):
    """The DNSKEY key tag per RFC 4034 Appendix B (16-bit word sum with carry folded in)."""
    acc = 0
    for i, byte in enumerate(rdata):
        acc += byte << 8 if i % 2 == 0 else byte
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def _wire_name(name):
    """A domain name in canonical wire form, lowercased as RFC 4034 section 6.2 requires."""
    labels = [lbl for lbl in name.rstrip(".").lower().split(".") if lbl]
    return b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in labels) + b"\x00"


def _ds_digest_sha256(owner_name, dnskey_rdata):
    """The DS digest, RFC 4034 section 5.1.4: SHA-256 over wire(owner) || DNSKEY RDATA."""
    return hashlib.sha256(_wire_name(owner_name) + dnskey_rdata).hexdigest().upper()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Route 53 KSK's KeyTag, DigestValue, DSRecord and DNSKEYRecord recompute per RFC 4034 from
    the KMS public key and the zone name, in both the create response and GetDNSSEC.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_KeySigningKey.html
    """
    r53 = ctx.client("route53")
    kms, kms_arn = _dnssec_kms_key(ctx)
    zone_id, zone_name, _ns = _create_zone(ctx, r53, prefix="dnssec")
    ksk_name, created = _create_ksk(ctx, r53, zone_id, kms_arn)

    # The key material is read from KMS, independently of Route 53.
    der = kms.get_public_key(KeyId=kms_arn)["PublicKey"]
    key64 = _p256_raw_point(der)
    assert len(key64) == 64, (
        f"a P-256 public key is 64 raw bytes (X||Y), got {len(key64)}: {key64.hex()}"
    )

    flag = created["Flag"]
    sig_alg = created["SigningAlgorithmType"]
    dig_alg = created["DigestAlgorithmType"]
    assert flag == 257, (
        f"a key-SIGNING key is a DNSSEC secure-entry-point: Flag must be 257 (ZONE|SEP), got "
        f"{flag!r}"
    )
    assert (sig_alg, created["SigningAlgorithmMnemonic"]) == (13, "ECDSAP256SHA256"), (
        f"Route 53 DNSSEC signs with ECDSAP256SHA256 (algorithm 13), got "
        f"{sig_alg!r}/{created['SigningAlgorithmMnemonic']!r}"
    )
    assert (dig_alg, created["DigestAlgorithmMnemonic"]) == (2, "SHA-256"), (
        f"the DS digest type must be SHA-256 (2), got {dig_alg!r}/"
        f"{created['DigestAlgorithmMnemonic']!r}"
    )
    assert base64.b64decode(created["PublicKey"]) == key64, (
        f"PublicKey must be the base64 of the KMS key's own 64-byte P-256 point, got "
        f"{created['PublicKey']!r} for {base64.b64encode(key64).decode()!r}"
    )

    rdata = _dnskey_rdata(flag, sig_alg, key64)
    expected_tag = _key_tag(rdata)
    expected_digest = _ds_digest_sha256(zone_name, rdata)

    assert created["KeyTag"] == expected_tag, (
        f"KeyTag must be the RFC 4034 Appendix B tag of the DNSKEY RDATA: expected "
        f"{expected_tag}, Route 53 reported {created['KeyTag']} (rdata {rdata.hex()})"
    )
    assert created["DigestValue"].upper() == expected_digest, (
        f"DigestValue must be SHA-256(wire({zone_name}) || DNSKEY rdata): expected "
        f"{expected_digest}, Route 53 reported {created['DigestValue']!r}"
    )

    ds_tokens = created["DSRecord"].split()
    assert len(ds_tokens) == 4, (
        f"a DS record's presentation form is 'keytag algorithm digesttype digest', 4 tokens; "
        f"DSRecord was {created['DSRecord']!r}"
    )
    assert ds_tokens[0] == str(expected_tag) and ds_tokens[1] == str(sig_alg), (
        f"DSRecord must lead with the recomputed key tag {expected_tag} and the signing algorithm "
        f"{sig_alg}, got {ds_tokens[:2]!r}"
    )
    assert ds_tokens[2] == str(dig_alg) and ds_tokens[3].upper() == expected_digest, (
        f"DSRecord must carry digest type {dig_alg} and the recomputed digest {expected_digest}, "
        f"got {ds_tokens[2:]!r}"
    )
    dnskey_tokens = created["DNSKEYRecord"].split()
    assert len(dnskey_tokens) == 4, (
        f"a DNSKEY record's presentation form is 'flags protocol algorithm publickey', 4 tokens; "
        f"DNSKEYRecord was {created['DNSKEYRecord']!r}"
    )
    assert dnskey_tokens[:3] == [str(flag), "3", str(sig_alg)], (
        f"DNSKEYRecord must lead with flags {flag}, protocol 3 and algorithm {sig_alg}, got "
        f"{dnskey_tokens[:3]!r}"
    )
    assert base64.b64decode(dnskey_tokens[3]) == key64, (
        f"DNSKEYRecord's key field must be the same 64-byte point KMS holds, got "
        f"{dnskey_tokens[3]!r}"
    )

    # An undelegated zone cannot sign, so ServeSignature stays NOT_SIGNING.
    dnssec = r53.get_dnssec(HostedZoneId=zone_id)
    assert dnssec["Status"]["ServeSignature"] == "NOT_SIGNING", (
        f"an undelegated zone cannot be signing; GetDNSSEC reported "
        f"{dnssec['Status'].get('ServeSignature')!r}"
    )
    matching = [k for k in dnssec["KeySigningKeys"] if k["Name"] == ksk_name]
    assert len(matching) == 1, (
        f"GetDNSSEC must report exactly one KSK named {ksk_name}, got "
        f"{[k.get('Name') for k in dnssec['KeySigningKeys']]!r}"
    )
    read = matching[0]
    assert read["Status"] == "ACTIVE", (
        f"the KSK was created with Status=ACTIVE, GetDNSSEC reports {read['Status']!r}"
    )
    assert read["KeyTag"] == expected_tag, (
        f"GetDNSSEC's KeyTag must be the same recomputed tag {expected_tag}, got {read['KeyTag']}"
    )
    assert read["DigestValue"].upper() == expected_digest, (
        f"GetDNSSEC's DigestValue must be the same recomputed digest {expected_digest}, got "
        f"{read['DigestValue']!r}"
    )
    assert base64.b64decode(read["PublicKey"]) == key64, (
        f"GetDNSSEC's PublicKey must still be the KMS key's own point, got {read['PublicKey']!r}"
    )
    assert read["DSRecord"] == created["DSRecord"], (
        f"the DS record a zone operator would publish must not drift between the create response "
        f"{created['DSRecord']!r} and GetDNSSEC {read['DSRecord']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
