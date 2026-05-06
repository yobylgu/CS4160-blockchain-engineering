from __future__ import annotations

import asyncio
from dataclasses import dataclass

from ipv8.community import Community, CommunitySettings
from ipv8.messaging.interfaces.udp.endpoint import Address
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.messaging.payload_headers import BinMemberAuthenticationPayload
from ipv8.peer import Peer


COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

SERVER_PUBKEY = bytes.fromhex(
    "4c69624e61434c504b3a"
    "86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27e"
    "f319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)

DIFFICULTY_BITS = 28


@dataclass
class SubmitPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


@dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


# DataClassPayload only runs vp_compile on the first instantiation. ResponsePayload is only
# ever instantiated during incoming unpack, so without a forced instantiation here the very
# first server response races the compile and fails to parse.
SubmitPayload("", "", 0)
ResponsePayload(False, "")


class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.response_future: asyncio.Future = asyncio.get_running_loop().create_future()
        self.add_message_handler(ResponsePayload, self.on_response)

    def on_response(self, source_address: Address, data: bytes) -> None:
        # Filter on the raw auth pubkey BEFORE signature verification: the community is shared
        # with classmates, so we receive plenty of msg_id=2 traffic with non-curve25519 auth
        # headers that would otherwise blow up _verify_signature.
        try:
            auth, _ = self.serializer.unpack_serializable(
                BinMemberAuthenticationPayload, data, offset=23
            )
        except Exception:  # noqa: BLE001
            return
        if auth.public_key_bin != SERVER_PUBKEY:
            return
        # Match @lazy_wrapper's unpack flow exactly: the lab server frames responses as
        # [auth][user_payload][sig] with NO GlobalTimeDistributionPayload, so we can't use
        # _ez_unpack_auth (which inserts one).
        try:
            signature_valid, remainder = self._verify_signature(auth, data)
            if not signature_valid:
                self.logger.warning("server response failed signature verification")
                return
            unpacked = self.serializer.unpack_serializable_list(
                [ResponsePayload], remainder, offset=23
            )
            payload = unpacked[0]
        except Exception:  # noqa: BLE001
            self.logger.warning("malformed signed response from server", exc_info=True)
            return
        if not self.response_future.done():
            self.response_future.set_result((payload.success, payload.message))

    def find_server(self) -> Peer | None:
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == SERVER_PUBKEY:
                return peer
        return None
