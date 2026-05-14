from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from ipv8.community import Community, CommunitySettings
from ipv8.keyvault.crypto import default_eccrypto
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8.peer import Peer


COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")

SERVER_PUBKEY = bytes.fromhex(
    "4c69624e61434c504b3a"
    "82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553"
    "cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
)

GROUP_SIZE = 3
ROUND_COUNT = 3

REGISTER_RETRY_SECONDS = 1.0
CHALLENGE_RETRY_SECONDS = 0.5
RELAY_RETRY_SECONDS = 0.25
SIGNATURE_RETRY_SECONDS = 0.25
BUNDLE_RETRY_SECONDS = 0.75

DEBUG_RX = True


def _dbg(msg: str) -> None:
    if DEBUG_RX:
        print(msg)


# --- Server protocol (msg_ids 1-6), formats fixed by assignment_2.md ---

@vp_compile
class RegisterPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenH", "varlenH", "varlenH"]
    names = ["member1_key", "member2_key", "member3_key"]


@vp_compile
class RegistrationResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8", "varlenHutf8"]
    names = ["success", "group_id", "message"]


@vp_compile
class ChallengeRequestPayload(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]


@vp_compile
class ChallengeResponsePayload(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]


@vp_compile
class SignatureBundlePayload(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]


@vp_compile
class RoundResultPayload(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]


# --- Group-internal protocol (msg_ids 7-9), wire-compatible with teammate B ---

@vp_compile
class TeamNoncePayload(VariablePayload):
    msg_id = 7
    format_list = ["varlenHutf8", "q", "varlenH", "d", "q"]
    names = ["group_id", "round_number", "nonce", "deadline", "submitter_index"]


@vp_compile
class TeamSignaturePayload(VariablePayload):
    msg_id = 8
    format_list = ["varlenHutf8", "q", "varlenH", "q", "varlenH"]
    names = ["group_id", "round_number", "nonce_hash", "signer_index", "signature"]


@vp_compile
class TeamAckPayload(VariablePayload):
    msg_id = 9
    format_list = ["varlenHutf8", "q", "varlenH", "varlenHutf8", "q"]
    names = ["group_id", "round_number", "nonce_hash", "ack_kind", "signer_index"]


@dataclass
class Lab2Config:
    member_keys: list[bytes]
    group_id: Optional[str]
    should_register: bool


@dataclass
class RoundState:
    round_number: int = 0
    nonce: Optional[bytes] = None
    deadline: float = 0.0
    nonce_source_is_server: bool = False
    signatures: dict[int, bytes] = field(default_factory=dict)
    signature_acks: set[int] = field(default_factory=set)
    outgoing_signature: Optional[TeamSignaturePayload] = None
    submitted_round: int = 0
    result_received_round: int = 0
    last_nonce_relay_at: float = 0.0
    last_signature_sent_at: float = 0.0
    last_bundle_sent_at: float = 0.0


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class Lab2Community(Community):
    community_id = COMMUNITY_ID
    config: Lab2Config

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.member_keys: list[bytes] = self.config.member_keys
        self.member_key_hexes: list[str] = [k.hex() for k in self.member_keys]
        self.member_public_keys = [default_eccrypto.key_from_public_bin(k) for k in self.member_keys]
        self.member_key_set: set[str] = set(self.member_key_hexes)

        self.group_id: Optional[str] = self.config.group_id
        self.should_register: bool = self.config.should_register

        self.my_pubkey: bytes = self.my_peer.public_key.key_to_bin()
        self.my_pubkey_hex: str = self.my_pubkey.hex()
        if self.my_pubkey_hex not in self.member_key_set:
            raise RuntimeError("local IPv8 key is not in --member*-key set")
        self.local_index: int = self.member_key_hexes.index(self.my_pubkey_hex)

        self.server_peer: Optional[Peer] = None
        self.member_peers: dict[int, Peer] = {}
        self._logged_server = False
        self._logged_members: set[int] = set()

        self.registration_done = False
        self.last_register_sent_at = 0.0
        self.waiting_challenge_round: Optional[int] = None
        self.last_challenge_request_at = 0.0
        self.rounds_completed = 0
        self.finished = False
        self.round_state = RoundState()

        self.add_message_handler(RegistrationResponsePayload, self.on_registration_response)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)
        self.add_message_handler(TeamNoncePayload, self.on_team_nonce)
        self.add_message_handler(TeamSignaturePayload, self.on_team_signature)
        self.add_message_handler(TeamAckPayload, self.on_team_ack)

    def started(self) -> None:
        print(f"Joined Lab 2 community as member {self.local_index + 1}.")
        print(f"  my pubkey  = {self.my_pubkey_hex}")
        print(f"  community  = {self.community_id.hex()}")
        print(f"  server     = {SERVER_PUBKEY.hex()}")
        print(f"  group_id   = {self.group_id}")
        print(f"  register   = {self.should_register}")
        self.register_task("tick", self.tick, interval=0.1, delay=0)

    # --- main scheduler ---

    async def tick(self) -> None:
        if self.finished:
            return
        now = time.time()
        self._discover_peers()
        self._retry_registration(now)
        self._maybe_start_round_one(now)
        self._retry_challenge_request(now)
        self._retry_nonce_relay(now)
        self._retry_signature(now)
        self._retry_bundle(now)

    def _discover_peers(self) -> None:
        for peer in self.get_peers():
            peer_key_hex = peer.public_key.key_to_bin().hex()
            if peer_key_hex == SERVER_PUBKEY.hex():
                self.server_peer = peer
                if not self._logged_server:
                    print(f"Found server peer at {peer.address}")
                    self._logged_server = True
                continue
            if peer_key_hex == self.my_pubkey_hex:
                continue
            if peer_key_hex not in self.member_key_set:
                continue
            idx = self.member_key_hexes.index(peer_key_hex)
            self.member_peers[idx] = peer
            if idx not in self._logged_members:
                print(f"Found teammate member {idx + 1} at {peer.address}")
                self._logged_members.add(idx)

    def _all_teammates_found(self) -> bool:
        return len(self.member_peers) == GROUP_SIZE - 1

    @staticmethod
    def submitter_index_for_round(round_number: int) -> int:
        return (round_number - 1) % GROUP_SIZE

    # --- registration ---

    def _retry_registration(self, now: float) -> None:
        if not self.should_register or self.registration_done or self.server_peer is None:
            return
        if now - self.last_register_sent_at < REGISTER_RETRY_SECONDS:
            return
        self.ez_send(
            self.server_peer,
            RegisterPayload(self.member_keys[0], self.member_keys[1], self.member_keys[2]),
        )
        self.last_register_sent_at = now
        print("Sent group registration request.")

    @lazy_wrapper(RegistrationResponsePayload)
    def on_registration_response(self, peer: Peer, payload: RegistrationResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBKEY:
            return
        self.registration_done = True
        print(f"Registration response: success={payload.success} group_id={payload.group_id!r} message={payload.message!r}")
        if payload.success:
            self.group_id = payload.group_id
            self.config.group_id = payload.group_id
        else:
            self.finished = True

    # --- round flow ---

    def _maybe_start_round_one(self, now: float) -> None:
        if self.group_id is None:
            return
        if self.rounds_completed > 0 or self.round_state.round_number != 0:
            return
        if self.local_index != 0:
            return
        if self.server_peer is None or not self._all_teammates_found():
            return
        if self.waiting_challenge_round is not None:
            return
        self.waiting_challenge_round = 1
        self._send_challenge_request(1, now)

    def _retry_challenge_request(self, now: float) -> None:
        if (
            self.group_id is None
            or self.server_peer is None
            or self.waiting_challenge_round is None
        ):
            return
        # Have we already received the nonce for this requested round?
        st = self.round_state
        if st.round_number == self.waiting_challenge_round and st.nonce is not None:
            return
        if now - self.last_challenge_request_at < CHALLENGE_RETRY_SECONDS:
            return
        self._send_challenge_request(self.waiting_challenge_round, now)

    def _send_challenge_request(self, round_number: int, now: Optional[float] = None) -> None:
        if self.group_id is None or self.server_peer is None:
            return
        self.ez_send(self.server_peer, ChallengeRequestPayload(self.group_id))
        self.last_challenge_request_at = time.time() if now is None else now
        print(f"Requested challenge for round {round_number}.")

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, payload: ChallengeResponsePayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBKEY:
            return
        print(f"Challenge response: round={payload.round_number} deadline={payload.deadline:.3f}")
        self._install_nonce(payload.round_number, payload.nonce, payload.deadline, True)

    def _install_nonce(self, round_number: int, nonce: bytes, deadline: float, from_server: bool) -> None:
        if round_number < 1 or round_number > ROUND_COUNT:
            return
        if len(nonce) != 32:
            print(f"Ignored nonce with bad length {len(nonce)}.")
            return
        if round_number <= self.rounds_completed:
            return

        st = self.round_state
        is_new = st.round_number != round_number or st.nonce != nonce
        if is_new:
            self.round_state = RoundState(
                round_number=round_number,
                nonce=nonce,
                deadline=deadline,
                nonce_source_is_server=from_server,
            )
            st = self.round_state
            print(
                f"Round {round_number} nonce installed; "
                f"submitter is member {self.submitter_index_for_round(round_number) + 1}."
            )
        else:
            st.deadline = deadline
            st.nonce_source_is_server = st.nonce_source_is_server or from_server

        if self.waiting_challenge_round == round_number:
            self.waiting_challenge_round = None

        self._add_own_signature()
        if from_server:
            self._broadcast_nonce(time.time())
        self._prepare_outgoing_signature()
        self._retry_bundle(time.time())

    def _add_own_signature(self) -> None:
        st = self.round_state
        if st.nonce is None or self.local_index in st.signatures:
            return
        sig = self.crypto.create_signature(self.my_peer.key, st.nonce)
        st.signatures[self.local_index] = sig
        print(f"Signed nonce for round {st.round_number}.")

    def _prepare_outgoing_signature(self) -> None:
        st = self.round_state
        if st.nonce is None or self.group_id is None:
            return
        submitter = self.submitter_index_for_round(st.round_number)
        if self.local_index == submitter:
            return
        sig = st.signatures.get(self.local_index)
        if sig is None:
            return
        st.outgoing_signature = TeamSignaturePayload(
            self.group_id,
            st.round_number,
            _sha256(st.nonce),
            self.local_index,
            sig,
        )
        st.last_signature_sent_at = 0.0
        self._retry_signature(time.time())

    def _broadcast_nonce(self, now: float) -> None:
        st = self.round_state
        if self.group_id is None or st.nonce is None:
            return
        submitter = self.submitter_index_for_round(st.round_number)
        payload = TeamNoncePayload(
            self.group_id,
            st.round_number,
            st.nonce,
            st.deadline,
            submitter,
        )
        for idx, peer in self.member_peers.items():
            if idx == self.local_index:
                continue
            self.ez_send(peer, payload)
        st.last_nonce_relay_at = now
        print(f"Broadcast nonce for round {st.round_number}.")

    def _retry_nonce_relay(self, now: float) -> None:
        st = self.round_state
        if st.nonce is None or not st.nonce_source_is_server:
            return
        if st.round_number <= self.rounds_completed:
            return
        if st.result_received_round == st.round_number:
            return
        if now - st.last_nonce_relay_at < RELAY_RETRY_SECONDS:
            return
        self._broadcast_nonce(now)

    def _retry_signature(self, now: float) -> None:
        st = self.round_state
        if st.outgoing_signature is None:
            return
        if st.round_number <= self.rounds_completed:
            return
        if st.result_received_round == st.round_number:
            return
        if self.local_index in st.signature_acks:
            return
        if now - st.last_signature_sent_at < SIGNATURE_RETRY_SECONDS:
            return
        submitter = self.submitter_index_for_round(st.round_number)
        peer = self.member_peers.get(submitter)
        if peer is None:
            return
        self.ez_send(peer, st.outgoing_signature)
        st.last_signature_sent_at = now
        print(f"Sent signature for round {st.round_number} to member {submitter + 1}.")

    def _retry_bundle(self, now: float) -> None:
        st = self.round_state
        if st.nonce is None or st.round_number <= self.rounds_completed:
            return
        if st.result_received_round == st.round_number:
            return
        if self.local_index != self.submitter_index_for_round(st.round_number):
            return
        if len(st.signatures) != GROUP_SIZE:
            return
        if st.submitted_round == st.round_number and now - st.last_bundle_sent_at < BUNDLE_RETRY_SECONDS:
            return
        self._submit_bundle(now)

    def _submit_bundle(self, now: float) -> None:
        st = self.round_state
        if self.group_id is None or self.server_peer is None or st.nonce is None:
            return
        sigs = [st.signatures[i] for i in range(GROUP_SIZE)]
        # Local pre-verify so we don't waste a round-trip on a known-bad share.
        for i, sig in enumerate(sigs):
            if not self.crypto.is_valid_signature(self.member_public_keys[i], st.nonce, sig):
                print(f"Pre-verify failed for member {i + 1}; dropping share.")
                st.signatures.pop(i, None)
                return
        self.ez_send(
            self.server_peer,
            SignatureBundlePayload(self.group_id, st.round_number, sigs[0], sigs[1], sigs[2]),
        )
        st.submitted_round = st.round_number
        st.last_bundle_sent_at = now
        print(f"Submitted bundle for round {st.round_number}.")

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer: Peer, payload: RoundResultPayload) -> None:
        if peer.public_key.key_to_bin() != SERVER_PUBKEY:
            return
        print(
            f"Round result: success={payload.success} round={payload.round_number} "
            f"completed={payload.rounds_completed} message={payload.message!r}"
        )
        if payload.success:
            self.round_state.result_received_round = payload.round_number
            self.rounds_completed = max(self.rounds_completed, payload.rounds_completed)
            if payload.rounds_completed >= ROUND_COUNT:
                self.finished = True
                print("All 3 rounds completed.")
                return
            next_round = payload.round_number + 1
            requester = self.submitter_index_for_round(next_round)
            if next_round == 3:
                requester = 1
            if self.local_index == requester:
                self.waiting_challenge_round = next_round
                self._send_challenge_request(next_round)
            return

        msg = payload.message.lower()
        terminal_markers = (
            "budget exceeded",
            "group not found",
            "not a member",
            "submitter already used",
            "wrong round number",
            "already completed",
        )
        if any(m in msg for m in terminal_markers):
            self.round_state.result_received_round = payload.round_number
            self.finished = True
            print("Terminal server rejection; stopping.")
            return
        if "invalid signature" in msg:
            # Drop submitter state; retries will re-collect signatures.
            self.round_state.submitted_round = 0
            print("Invalid signature reported; waiting for fresh shares.")
            return
        if "no active challenge" in msg and payload.round_number < ROUND_COUNT:
            next_round = payload.round_number + 1
            self.waiting_challenge_round = next_round
            self._send_challenge_request(next_round)
            return
        print("Non-terminal rejection; retries remain active.")

    # --- group-internal handlers ---

    def _member_index_for(self, peer: Peer) -> Optional[int]:
        h = peer.public_key.key_to_bin().hex()
        if h not in self.member_key_set:
            return None
        return self.member_key_hexes.index(h)

    def _valid_group(self, group_id: str) -> bool:
        return self.group_id is not None and group_id == self.group_id

    @lazy_wrapper(TeamNoncePayload)
    def on_team_nonce(self, peer: Peer, payload: TeamNoncePayload) -> None:
        _dbg(
            "RX TeamNoncePayload from "
            f"{peer.address} group={payload.group_id!r} round={payload.round_number} "
            f"submitter={payload.submitter_index + 1} nonce_len={len(payload.nonce)}"
        )
        sender = self._member_index_for(peer)
        if sender is None or not self._valid_group(payload.group_id):
            _dbg(
                "Drop TeamNoncePayload: "
                f"sender={sender} valid_group={self._valid_group(payload.group_id)}"
            )
            return
        if payload.submitter_index != self.submitter_index_for_round(payload.round_number):
            _dbg(
                "Drop TeamNoncePayload: "
                f"submitter_index mismatch (got {payload.submitter_index + 1}, "
                f"expected {self.submitter_index_for_round(payload.round_number) + 1})"
            )
            return
        print(f"Nonce relay for round {payload.round_number} from member {sender + 1}.")
        self._install_nonce(payload.round_number, payload.nonce, payload.deadline, False)

    @lazy_wrapper(TeamSignaturePayload)
    def on_team_signature(self, peer: Peer, payload: TeamSignaturePayload) -> None:
        _dbg(
            "RX TeamSignaturePayload from "
            f"{peer.address} group={payload.group_id!r} round={payload.round_number} "
            f"signer={payload.signer_index + 1}"
        )
        sender = self._member_index_for(peer)
        if sender is None or not self._valid_group(payload.group_id):
            _dbg(
                "Drop TeamSignaturePayload: "
                f"sender={sender} valid_group={self._valid_group(payload.group_id)}"
            )
            return
        if sender != payload.signer_index:
            _dbg(
                "Drop TeamSignaturePayload: "
                f"signer_index mismatch (sender {sender + 1}, payload {payload.signer_index + 1})"
            )
            return
        st = self.round_state
        if payload.round_number != st.round_number or st.nonce is None:
            _dbg(
                "Drop TeamSignaturePayload: "
                f"round/nonce mismatch (payload round {payload.round_number}, "
                f"state round {st.round_number}, nonce_set={st.nonce is not None})"
            )
            return
        if payload.nonce_hash != _sha256(st.nonce):
            _dbg("Drop TeamSignaturePayload: nonce_hash mismatch")
            return
        if self.local_index != self.submitter_index_for_round(payload.round_number):
            _dbg(
                "Drop TeamSignaturePayload: "
                f"not submitter (local {self.local_index + 1}, "
                f"expected {self.submitter_index_for_round(payload.round_number) + 1})"
            )
            return
        signer_pk = self.member_public_keys[payload.signer_index]
        if not self.crypto.is_valid_signature(signer_pk, st.nonce, payload.signature):
            print(f"Ignored invalid signature from member {payload.signer_index + 1}.")
            return
        st.signatures[payload.signer_index] = payload.signature
        self.ez_send(
            peer,
            TeamAckPayload(
                self.group_id or "",
                payload.round_number,
                payload.nonce_hash,
                "signature",
                payload.signer_index,
            ),
        )
        print(
            f"Accepted signature from member {payload.signer_index + 1} "
            f"for round {payload.round_number} ({len(st.signatures)}/3)."
        )
        self._retry_bundle(time.time())

    @lazy_wrapper(TeamAckPayload)
    def on_team_ack(self, peer: Peer, payload: TeamAckPayload) -> None:
        _dbg(
            "RX TeamAckPayload from "
            f"{peer.address} group={payload.group_id!r} round={payload.round_number} "
            f"ack_kind={payload.ack_kind!r} signer={payload.signer_index + 1}"
        )
        sender = self._member_index_for(peer)
        if sender is None or not self._valid_group(payload.group_id):
            _dbg(
                "Drop TeamAckPayload: "
                f"sender={sender} valid_group={self._valid_group(payload.group_id)}"
            )
            return
        if payload.ack_kind != "signature":
            _dbg("Drop TeamAckPayload: ack_kind mismatch")
            return
        st = self.round_state
        if payload.round_number != st.round_number or st.nonce is None:
            _dbg(
                "Drop TeamAckPayload: "
                f"round/nonce mismatch (payload round {payload.round_number}, "
                f"state round {st.round_number}, nonce_set={st.nonce is not None})"
            )
            return
        if payload.nonce_hash != _sha256(st.nonce):
            _dbg("Drop TeamAckPayload: nonce_hash mismatch")
            return
        if payload.signer_index != self.local_index:
            _dbg(
                "Drop TeamAckPayload: signer_index mismatch "
                f"(payload {payload.signer_index + 1}, local {self.local_index + 1})"
            )
            return
        if sender != self.submitter_index_for_round(payload.round_number):
            _dbg(
                "Drop TeamAckPayload: sender not submitter "
                f"(sender {sender + 1}, expected "
                f"{self.submitter_index_for_round(payload.round_number) + 1})"
            )
            return
        st.signature_acks.add(payload.signer_index)
        print(f"Signature ACK received for round {payload.round_number}.")

    # --- public helper for the client to wait on ---

    async def wait_until_done(self, poll: float = 0.2) -> None:
        while not self.finished:
            await asyncio.sleep(poll)
