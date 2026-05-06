from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8_service import IPv8

from lab1.community import (
    DIFFICULTY_BITS,
    Lab1Community,
    SERVER_PUBKEY,
    SubmitPayload,
)
from lab1.miner import has_leading_zero_bits, mine, pow_hash


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CS4160 Lab 1 — IPv8 PoW client.",
    )
    parser.add_argument("--email", required=True,
                        help="Your TU Delft email (must end in @tudelft.nl or @student.tudelft.nl).")
    parser.add_argument("--github-url", required=True,
                        help="Public GitHub repo URL containing this client.")
    parser.add_argument("--key", default="lab1_key.pem",
                        help="Path to your IPv8 private key (.pem). Default: lab1_key.pem.")
    parser.add_argument("--port", type=int, default=0,
                        help="UDP port to bind to. Default: 0 (OS-assigned).")
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of mining worker processes. Default: cpu_count().")
    parser.add_argument("--self-test", action="store_true",
                        help="Mine at low difficulty (12 bits) and exit; does NOT contact the server.")
    parser.add_argument("--difficulty", type=int, default=None,
                        help="Override difficulty bits (advanced; default = 28 for real run, 12 for self-test).")
    return parser.parse_args()


def validate_email(email: str) -> None:
    if "\n" in email or "\r" in email:
        raise ValueError("email contains newline characters")
    if any(ch.isspace() for ch in email):
        raise ValueError("email contains whitespace")
    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        raise ValueError("email must end in @tudelft.nl or @student.tudelft.nl")
    if len(email.encode("utf-8")) > 254:
        raise ValueError("email exceeds 254 bytes")


def validate_url(url: str) -> None:
    if not url:
        raise ValueError("github_url is empty")
    if len(url.encode("utf-8")) > 512:
        raise ValueError("github_url exceeds 512 bytes")
    for ch in url:
        if ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError(f"github_url contains forbidden character {ch!r}")


async def run_self_test(email: str, github_url: str, bits: int, workers: int | None) -> int:
    print(f"Self-test: mining {bits}-bit PoW (no network).")
    print(f"  email      = {email!r}")
    print(f"  github_url = {github_url!r}")
    nonce, digest, elapsed = await mine(email, github_url, bits, workers)
    print(f"Found nonce={nonce} in {elapsed:.2f}s")
    print(f"  digest = {digest.hex()}")
    verify = pow_hash(email, github_url, nonce)
    assert verify == digest, "verify hash mismatch"
    assert has_leading_zero_bits(digest, bits), "leading zero bit check failed"
    print(f"  verified: {bits} leading zero bits OK")
    return 0


def _nonce_cache_path(key_path: str) -> str:
    base, _ = os.path.splitext(key_path)
    return base + ".nonce.json"


def load_cached_nonce(key_path: str, email: str, github_url: str, bits: int) -> int | None:
    path = _nonce_cache_path(key_path)
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if (data.get("email") != email
            or data.get("github_url") != github_url
            or data.get("bits") != bits):
        return None
    nonce = data.get("nonce")
    if not isinstance(nonce, int):
        return None
    digest = pow_hash(email, github_url, nonce)
    if not has_leading_zero_bits(digest, bits):
        return None
    return nonce


def save_cached_nonce(key_path: str, email: str, github_url: str, bits: int, nonce: int) -> None:
    path = _nonce_cache_path(key_path)
    with open(path, "w") as f:
        json.dump({"email": email, "github_url": github_url, "bits": bits, "nonce": nonce}, f)


async def run_real(args: argparse.Namespace) -> int:
    bits = args.difficulty if args.difficulty is not None else DIFFICULTY_BITS

    cached = load_cached_nonce(args.key, args.email, args.github_url, bits)
    if cached is not None:
        nonce = cached
        digest = pow_hash(args.email, args.github_url, nonce)
        print(f"Reusing cached nonce={nonce} (verified locally)")
        print(f"  digest = {digest.hex()}")
    else:
        print(f"Mining {bits}-bit PoW for:")
        print(f"  email      = {args.email!r}")
        print(f"  github_url = {args.github_url!r}")
        nonce, digest, mining_elapsed = await mine(args.email, args.github_url, bits, args.workers)
        print(f"Found nonce={nonce} in {mining_elapsed:.2f}s")
        print(f"  digest = {digest.hex()}")
        assert has_leading_zero_bits(digest, bits), "PoW verification failed locally"
        save_cached_nonce(args.key, args.email, args.github_url, bits, nonce)
        print(f"  cached nonce at {_nonce_cache_path(args.key)}")

    print(f"Starting IPv8 (key={args.key}, port={args.port}) ...")
    builder = ConfigBuilder().clear_keys().clear_overlays()
    builder.set_port(args.port)
    builder.add_key("lab1", "curve25519", args.key)
    builder.add_overlay(
        "Lab1Community",
        "lab1",
        [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    try:
        community: Lab1Community = ipv8.get_overlay(Lab1Community)
        print(f"  my pubkey = {community.my_peer.public_key.key_to_bin().hex()}")
        print(f"  community = {community.community_id.hex()}")
        print(f"  server    = {SERVER_PUBKEY.hex()}")

        print("Discovering server peer (this can take 30s–several minutes) ...")
        server = None
        ticks = 0
        while server is None:
            server = community.find_server()
            if server is not None:
                break
            await asyncio.sleep(2)
            ticks += 1
            if ticks % 5 == 0:
                peers = community.get_peers()
                print(f"  ... {len(peers)} peer(s) in community after {ticks * 2}s; server not yet seen")
        print(f"Found server peer at {server.address}")

        submission = SubmitPayload(args.email, args.github_url, nonce)

        async def resender() -> None:
            attempt = 0
            while not community.response_future.done():
                attempt += 1
                community.ez_send(server, submission)
                print(f"  submission sent (attempt {attempt}); waiting for response ...")
                try:
                    await asyncio.wait_for(asyncio.shield(community.response_future), timeout=15.0)
                    return
                except asyncio.TimeoutError:
                    continue

        resend_task = asyncio.create_task(resender())
        success, message = await community.response_future
        resend_task.cancel()
        try:
            await resend_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass

        print()
        print("=" * 60)
        print(f"Server response: success={success}")
        print(f"                 message={message!r}")
        print("=" * 60)
        return 0 if success else 1
    finally:
        await ipv8.stop()


async def amain() -> int:
    args = parse_args()
    try:
        validate_email(args.email)
        validate_url(args.github_url)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.self_test:
        bits = args.difficulty if args.difficulty is not None else 12
        return await run_self_test(args.email, args.github_url, bits, args.workers)
    return await run_real(args)


def main() -> None:
    try:
        sys.exit(asyncio.run(amain()))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
