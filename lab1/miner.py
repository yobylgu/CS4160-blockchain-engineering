from __future__ import annotations

import asyncio
import hashlib
import multiprocessing as mp
import os
import struct
import time
from concurrent.futures import ThreadPoolExecutor


def pow_hash(email: str, github_url: str, nonce: int) -> bytes:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    return hashlib.sha256(prefix + struct.pack(">q", nonce)).digest()


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    full_bytes, rem = divmod(bits, 8)
    if any(b != 0 for b in digest[:full_bytes]):
        return False
    if rem == 0:
        return True
    return digest[full_bytes] >> (8 - rem) == 0


def _worker(
    worker_id: int,
    stride: int,
    prefix: bytes,
    bits: int,
    stop_event,
    result_queue,
    progress_queue,
) -> None:
    full_bytes, rem = divmod(bits, 8)
    threshold_byte = 1 << (8 - rem) if rem else None
    sha256 = hashlib.sha256
    pack = struct.Struct(">q").pack

    nonce = worker_id
    report_every = 1 << 18
    last_report = nonce
    while not stop_event.is_set():
        digest = sha256(prefix + pack(nonce)).digest()
        ok = True
        for i in range(full_bytes):
            if digest[i] != 0:
                ok = False
                break
        if ok and threshold_byte is not None and digest[full_bytes] >= threshold_byte:
            ok = False
        if ok:
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += stride
        if nonce - last_report >= report_every:
            progress_queue.put((worker_id, nonce, nonce - last_report))
            last_report = nonce


def _mine_sync(email: str, github_url: str, bits: int, num_workers: int | None = None):
    if num_workers is None:
        num_workers = max(1, (os.cpu_count() or 1))
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"

    ctx = mp.get_context("spawn")
    stop_event = ctx.Event()
    result_queue: mp.Queue = ctx.Queue()
    progress_queue: mp.Queue = ctx.Queue()

    processes = [
        ctx.Process(
            target=_worker,
            args=(i, num_workers, prefix, bits, stop_event, result_queue, progress_queue),
            daemon=True,
        )
        for i in range(num_workers)
    ]
    start = time.monotonic()
    for p in processes:
        p.start()

    last_print = start
    total_attempts = 0
    try:
        while True:
            try:
                nonce, digest = result_queue.get(timeout=0.5)
                break
            except Exception:  # noqa: BLE001
                pass
            while True:
                try:
                    _wid, _n, delta = progress_queue.get_nowait()
                    total_attempts += delta
                except Exception:  # noqa: BLE001
                    break
            now = time.monotonic()
            if now - last_print >= 5.0:
                elapsed = now - start
                rate = total_attempts / elapsed if elapsed > 0 else 0
                print(f"  mining ... {total_attempts:,} hashes in {elapsed:.1f}s "
                      f"({rate/1e6:.2f} MH/s, {num_workers} workers)")
                last_print = now
    finally:
        stop_event.set()
        for p in processes:
            p.join(timeout=2.0)
            if p.is_alive():
                p.terminate()
                p.join(timeout=1.0)

    elapsed = time.monotonic() - start
    return nonce, digest, elapsed


async def mine(email: str, github_url: str, bits: int, num_workers: int | None = None):
    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return await loop.run_in_executor(
            pool, _mine_sync, email, github_url, bits, num_workers
        )
