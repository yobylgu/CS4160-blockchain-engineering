from __future__ import annotations

import argparse
import asyncio
import sys

from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8_service import IPv8

from lab2.community import GROUP_SIZE, Lab2Community, Lab2Config


IPV8_PUBKEY_LEN = 74  # LibNaCLPK:(10 bytes prefix) + 64-byte public key


def parse_member_key(value: str, label: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} must be valid hex") from exc
    if len(raw) != IPV8_PUBKEY_LEN:
        raise argparse.ArgumentTypeError(
            f"{label} must be exactly {IPV8_PUBKEY_LEN} bytes "
            f"({IPV8_PUBKEY_LEN * 2} hex chars); got {len(raw)} bytes. "
            "Get the value from peer.public_key.key_to_bin().hex()."
        )
    return raw


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CS4160 Lab 2 — coordinated group signing client.")
    parser.add_argument("--key-file", default="lab1_key.pem",
                        help="IPv8 private key (.pem). Default: lab1_key.pem (reuses Lab 1 key).")
    parser.add_argument("--member1-key", required=True, help="Member 1 IPv8 pubkey hex (148 chars).")
    parser.add_argument("--member2-key", required=True, help="Member 2 IPv8 pubkey hex (148 chars).")
    parser.add_argument("--member3-key", required=True, help="Member 3 IPv8 pubkey hex (148 chars).")
    parser.add_argument("--group-id", default=None,
                        help="Registered Lab 2 group id (required unless --register).")
    parser.add_argument("--register", action="store_true",
                        help="Register the trio with the server, then continue into the rounds.")
    parser.add_argument("--port", type=int, default=0,
                        help="UDP port. Default: 0 (OS-assigned).")
    return parser.parse_args()


def build_config(args: argparse.Namespace) -> Lab2Config:
    member_keys = [
        parse_member_key(args.member1_key, "--member1-key"),
        parse_member_key(args.member2_key, "--member2-key"),
        parse_member_key(args.member3_key, "--member3-key"),
    ]
    if len(set(member_keys)) != GROUP_SIZE:
        raise ValueError("--member1/2/3-key must be pairwise distinct")
    if not args.register and not args.group_id:
        raise ValueError("provide --group-id or pass --register to register first")
    return Lab2Config(
        member_keys=member_keys,
        group_id=args.group_id,
        should_register=args.register,
    )


async def amain() -> int:
    args = parse_args()
    try:
        config = build_config(args)
    except (ValueError, argparse.ArgumentTypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    Lab2Community.config = config

    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.add_key("lab2", "curve25519", args.key_file)
    builder.add_overlay(
        "Lab2Community",
        "lab2",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab2Community": Lab2Community})
    await ipv8.start()
    try:
        community: Lab2Community = ipv8.get_overlay(Lab2Community)
        await community.wait_until_done()
        return 0 if community.rounds_completed >= 3 else 1
    finally:
        await ipv8.stop()


def main() -> None:
    try:
        sys.exit(asyncio.run(amain()))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
