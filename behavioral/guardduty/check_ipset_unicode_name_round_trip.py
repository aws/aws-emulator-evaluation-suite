"""ipset-unicode-name-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ipset-unicode-name-round-trip"
GROUP = "representation"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """GetIPSet returns an IPSet's name, location, TXT format and multi-script tag
    value byte-exact; the tag carries the unicode text because IPSet names allow only
    alphanumerics, spaces, - and _."""
    gd = ctx.client("guardduty")

    detector_id = gd.create_detector(Enable=True)["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))

    name = ctx.unique_name("sim2real-gd-ipset-")
    location = f"s3://{ctx.unique_name('sim2real-gd-ipset-bucket-')}/list.txt"
    # GuardDuty tag values only allow letters, numbers, spaces and a small fixed set
    # of punctuation (no em-dashes or other exotic punctuation), so this exercises
    # unicode-letter fidelity (Cyrillic, CJK, Latin-extended) using only spaces as
    # separators.
    unicode_value = "Список доверенных IP 信頼できるIPアドレス一覧 Ñoño Ünïcödé"

    resp = gd.create_ip_set(
        DetectorId=detector_id,
        Name=name,
        Format="TXT",
        Location=location,
        Activate=False,
        Tags={"sim2real-note": unicode_value},
    )
    ip_set_id = resp["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))

    got = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)
    assert got["Name"] == name, (got.get("Name"), name)
    assert got["Location"] == location, (got.get("Location"), location)
    assert got["Format"] == "TXT", (got.get("Format"), "TXT")
    assert got["Tags"]["sim2real-note"] == unicode_value, (got.get("Tags"), unicode_value)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
