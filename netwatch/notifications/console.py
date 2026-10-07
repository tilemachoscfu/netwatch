from typing import TextIO

from netwatch.models.records import Device


def clean_text(value: object) -> str:
    # Device names originate on an untrusted LAN. Strip control/terminal escape characters.
    return "".join(character if character.isprintable() else " " for character in str(value))


def notify_new_device(device: Device, stream: TextIO) -> None:
    print("NEW DEVICE DETECTED", file=stream)
    for label, value in (
        ("IP", device.ip),
        ("MAC", device.mac),
        ("HOSTNAME", device.hostname or "-"),
        ("VENDOR", device.vendor or "-"),
        ("TIME", device.first_seen),
    ):
        print(f"{label}: {clean_text(value)}", file=stream)
    stream.flush()
