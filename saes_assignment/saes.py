"""Reference implementation of the simplified AES (S-AES) algorithm.

The implementation follows Appendix D of *Cryptography and Network Security:
Principles and Practice*, 8th edition.  A block is written as four nibbles
``n0 n1 n2 n3`` and stored in the state matrix as::

    [ n0 n2 ]
    [ n1 n3 ]

All public block functions use integers in the range 0..0xffff.  Byte strings
use big-endian 16-bit blocks so that the representation is unambiguous across
different languages and platforms.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import CancelledError
from typing import Final, TypeAlias

BLOCK_BITS: Final = 16
BLOCK_MASK: Final = (1 << BLOCK_BITS) - 1
BYTE_MASK: Final = 0xFF
NIBBLE_MASK: Final = 0x0F
GF4_MODULUS: Final = 0b10011  # x^4 + x + 1
RCON1: Final = 0x80
RCON2: Final = 0x30

S_BOX: Final[tuple[tuple[int, ...], ...]] = (
    (0x9, 0x4, 0xA, 0xB),
    (0xD, 0x1, 0x8, 0x5),
    (0x6, 0x2, 0x0, 0x3),
    (0xC, 0xE, 0xF, 0x7),
)

INV_S_BOX: Final[tuple[tuple[int, ...], ...]] = (
    (0xA, 0x5, 0x9, 0xB),
    (0x1, 0x7, 0x8, 0xF),
    (0x6, 0x0, 0x2, 0x3),
    (0xC, 0x4, 0xD, 0xE),
)

State: TypeAlias = tuple[tuple[int, int], tuple[int, int]]
ProgressCallback: TypeAlias = Callable[[str, int, int], None]
KnownPair: TypeAlias = tuple[int, int]


def _validate_uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{name} must fit in {bits} bits")
    return value


def _validate_block(value: int, name: str = "block") -> int:
    return _validate_uint(value, BLOCK_BITS, name)


def parse_hex(value: str, bits: int, name: str = "value") -> int:
    """Parse a hexadecimal integer and validate its declared width."""

    if not isinstance(value, str):
        raise TypeError(f"{name} must be a hexadecimal string")
    text = value.strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    if not text:
        raise ValueError(f"{name} cannot be empty")
    valid_digits = bits // 4
    if len(text) > valid_digits or any(character not in "0123456789abcdefABCDEF" for character in text):
        raise ValueError(f"{name} must be at most {valid_digits} hexadecimal digits")
    return _validate_uint(int(text, 16), bits, name)


def format_hex(value: int, bits: int = BLOCK_BITS) -> str:
    """Format an integer with a fixed-width uppercase hexadecimal form."""

    _validate_uint(value, bits, "value")
    return f"{value:0{bits // 4}X}"


def _state_from_block(block: int) -> State:
    block = _validate_block(block)
    nibbles = tuple((block >> shift) & NIBBLE_MASK for shift in (12, 8, 4, 0))
    return ((nibbles[0], nibbles[2]), (nibbles[1], nibbles[3]))


def _block_from_state(state: State) -> int:
    return (
        (state[0][0] << 12)
        | (state[1][0] << 8)
        | (state[0][1] << 4)
        | state[1][1]
    )


def _sub_nibble(nibble: int, box: Sequence[Sequence[int]]) -> int:
    return box[(nibble >> 2) & 0x3][nibble & 0x3]


def _sub_byte(byte: int, box: Sequence[Sequence[int]]) -> int:
    return (_sub_nibble(byte >> 4, box) << 4) | _sub_nibble(byte & NIBBLE_MASK, box)


def sub_nibbles(block: int) -> int:
    """Apply the Appendix D S box independently to all four nibbles."""

    state = _state_from_block(block)
    transformed = tuple(
        tuple(_sub_nibble(state[row][column], S_BOX) for column in range(2))
        for row in range(2)
    )
    return _block_from_state(transformed)  # type: ignore[arg-type]


def inverse_sub_nibbles(block: int) -> int:
    """Apply the inverse Appendix D S box independently to all four nibbles."""

    state = _state_from_block(block)
    transformed = tuple(
        tuple(_sub_nibble(state[row][column], INV_S_BOX) for column in range(2))
        for row in range(2)
    )
    return _block_from_state(transformed)  # type: ignore[arg-type]


def shift_rows(block: int) -> int:
    """Leave row zero unchanged and rotate row one one nibble left."""

    state = _state_from_block(block)
    transformed: State = ((state[0][0], state[0][1]), (state[1][1], state[1][0]))
    return _block_from_state(transformed)


def inverse_shift_rows(block: int) -> int:
    """Inverse shift rows; for S-AES it is the same swap operation."""

    return shift_rows(block)


def gf4_multiply(left: int, right: int) -> int:
    """Multiply two GF(2^4) elements modulo x^4 + x + 1."""

    _validate_uint(left, 4, "left")
    _validate_uint(right, 4, "right")
    result = 0
    multiplicand = left
    multiplier = right
    for _ in range(4):
        if multiplier & 1:
            result ^= multiplicand
        high_bit = multiplicand & 0x8
        multiplicand = (multiplicand << 1) & NIBBLE_MASK
        if high_bit:
            multiplicand ^= GF4_MODULUS & NIBBLE_MASK
        multiplier >>= 1
    return result & NIBBLE_MASK


def mix_columns(block: int) -> int:
    """Apply the S-AES matrix [[1,4],[4,1]] to each state column."""

    state = _state_from_block(block)
    transformed: State = (
        (
            state[0][0] ^ gf4_multiply(0x4, state[1][0]),
            state[0][1] ^ gf4_multiply(0x4, state[1][1]),
        ),
        (
            gf4_multiply(0x4, state[0][0]) ^ state[1][0],
            gf4_multiply(0x4, state[0][1]) ^ state[1][1],
        ),
    )
    return _block_from_state(transformed)


def inverse_mix_columns(block: int) -> int:
    """Apply the inverse S-AES matrix [[9,2],[2,9]]."""

    state = _state_from_block(block)
    transformed: State = (
        (
            gf4_multiply(0x9, state[0][0]) ^ gf4_multiply(0x2, state[1][0]),
            gf4_multiply(0x9, state[0][1]) ^ gf4_multiply(0x2, state[1][1]),
        ),
        (
            gf4_multiply(0x2, state[0][0]) ^ gf4_multiply(0x9, state[1][0]),
            gf4_multiply(0x2, state[0][1]) ^ gf4_multiply(0x9, state[1][1]),
        ),
    )
    return _block_from_state(transformed)


def add_round_key(block: int, round_key: int) -> int:
    """XOR a 16-bit round key with a 16-bit state."""

    return _validate_block(block, "block") ^ _validate_block(round_key, "round_key")


def _g(word: int, round_constant: int) -> int:
    word = _validate_uint(word, 8, "word")
    rotated = ((word & 0x0F) << 4) | (word >> 4)
    return _sub_byte(rotated, S_BOX) ^ round_constant


def expand_key(key: int) -> tuple[int, int, int]:
    """Expand a 16-bit key into K0, K1 and K2."""

    key = _validate_block(key, "key")
    w0 = (key >> 8) & BYTE_MASK
    w1 = key & BYTE_MASK
    w2 = w0 ^ _g(w1, RCON1)
    w3 = w2 ^ w1
    w4 = w2 ^ _g(w3, RCON2)
    w5 = w4 ^ w3
    return ((w0 << 8) | w1, (w2 << 8) | w3, (w4 << 8) | w5)


def encrypt_block(plaintext: int, key: int) -> int:
    """Encrypt one 16-bit block with S-AES."""

    plaintext = _validate_block(plaintext, "plaintext")
    round_key0, round_key1, round_key2 = expand_key(key)

    state = add_round_key(plaintext, round_key0)
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_key1)
    state = sub_nibbles(state)
    state = shift_rows(state)
    return add_round_key(state, round_key2)


def decrypt_block(ciphertext: int, key: int) -> int:
    """Decrypt one 16-bit block with S-AES."""

    ciphertext = _validate_block(ciphertext, "ciphertext")
    round_key0, round_key1, round_key2 = expand_key(key)

    state = add_round_key(ciphertext, round_key2)
    state = inverse_shift_rows(state)
    state = inverse_sub_nibbles(state)
    state = add_round_key(state, round_key1)
    state = inverse_mix_columns(state)
    state = inverse_shift_rows(state)
    state = inverse_sub_nibbles(state)
    return add_round_key(state, round_key0)


def encrypt_trace(plaintext: int, key: int) -> tuple[int, tuple[tuple[str, int], ...]]:
    """Return ciphertext and named intermediate states for teaching/debugging."""

    plaintext = _validate_block(plaintext, "plaintext")
    round_key0, round_key1, round_key2 = expand_key(key)
    trace: list[tuple[str, int]] = [("Input", plaintext), ("K0", round_key0), ("AddRoundKey(K0)", add_round_key(plaintext, round_key0))]
    state = trace[-1][1]
    state = sub_nibbles(state)
    trace.append(("Round 1: SubNib", state))
    state = shift_rows(state)
    trace.append(("Round 1: ShiftRow", state))
    state = mix_columns(state)
    trace.append(("Round 1: MixColumn", state))
    state = add_round_key(state, round_key1)
    trace.append(("Round 1: AddRoundKey(K1)", state))
    state = sub_nibbles(state)
    trace.append(("Round 2: SubNib", state))
    state = shift_rows(state)
    trace.append(("Round 2: ShiftRow", state))
    state = add_round_key(state, round_key2)
    trace.extend((("Round key K1", round_key1), ("Round key K2", round_key2), ("Ciphertext", state)))
    return state, tuple(trace)


def _require_block_aligned(data: bytes, block_size: int = 2) -> bytes:
    data = _as_bytes(data)
    if len(data) % block_size:
        raise ValueError(f"data length must be a multiple of {block_size} bytes")
    return data


def _as_bytes(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    return bytes(data)


def _pkcs7_pad(data: bytes, block_size: int = 2) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes((padding_length,)) * padding_length


def _pkcs7_unpad(data: bytes, block_size: int = 2) -> bytes:
    data = _require_block_aligned(data, block_size)
    if not data:
        raise ValueError("cannot unpad an empty message")
    padding_length = data[-1]
    if not 1 <= padding_length <= block_size:
        raise ValueError("invalid S-AES padding")
    if data[-padding_length:] != bytes((padding_length,)) * padding_length:
        raise ValueError("invalid S-AES padding")
    return data[:-padding_length]


def _blocks_to_bytes(blocks: Iterable[int]) -> bytes:
    return b"".join(block.to_bytes(2, "big") for block in blocks)


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """Encrypt an arbitrary byte string using independent padded 2-byte blocks."""

    padded = _pkcs7_pad(_as_bytes(data))
    return _blocks_to_bytes(
        encrypt_block(int.from_bytes(padded[offset : offset + 2], "big"), key)
        for offset in range(0, len(padded), 2)
    )


def decrypt_bytes(data: bytes, key: int) -> bytes:
    """Decrypt bytes produced by :func:`encrypt_bytes` and remove padding."""

    aligned = _require_block_aligned(data)
    if not aligned:
        raise ValueError("ciphertext cannot be empty")
    plaintext = _blocks_to_bytes(
        decrypt_block(int.from_bytes(aligned[offset : offset + 2], "big"), key)
        for offset in range(0, len(aligned), 2)
    )
    return _pkcs7_unpad(plaintext)


def ascii_encrypt(text: str, key: int) -> bytes:
    """Encode an ASCII string and encrypt it as padded 2-byte blocks."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("text must contain ASCII characters only") from error
    return encrypt_bytes(data, key)


def ascii_decrypt(ciphertext: bytes, key: int) -> str:
    """Decrypt bytes produced by :func:`ascii_encrypt` and decode ASCII."""

    try:
        return decrypt_bytes(ciphertext, key).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("decrypted bytes are not valid ASCII") from error


def bytes_to_display(data: bytes) -> str:
    """Render arbitrary bytes without losing non-printable values."""

    return "".join(
        "\\\\" if value == 0x5C else chr(value) if 32 <= value <= 126 else f"\\x{value:02X}"
        for value in _as_bytes(data)
    )


def cbc_encrypt(plaintext: bytes, key: int, iv: int) -> bytes:
    """Encrypt a byte string in CBC mode with PKCS#7-style 2-byte padding."""

    key = _validate_block(key, "key")
    previous = _validate_block(iv, "iv")
    padded = _pkcs7_pad(_as_bytes(plaintext))
    encrypted_blocks: list[int] = []
    for offset in range(0, len(padded), 2):
        plaintext_block = int.from_bytes(padded[offset : offset + 2], "big")
        ciphertext_block = encrypt_block(plaintext_block ^ previous, key)
        encrypted_blocks.append(ciphertext_block)
        previous = ciphertext_block
    return _blocks_to_bytes(encrypted_blocks)


def cbc_decrypt(ciphertext: bytes, key: int, iv: int) -> bytes:
    """Decrypt CBC ciphertext and validate/remove its padding."""

    key = _validate_block(key, "key")
    previous = _validate_block(iv, "iv")
    aligned = _require_block_aligned(ciphertext)
    if not aligned:
        raise ValueError("ciphertext cannot be empty")
    plaintext_blocks: list[int] = []
    for offset in range(0, len(aligned), 2):
        ciphertext_block = int.from_bytes(aligned[offset : offset + 2], "big")
        plaintext_blocks.append(decrypt_block(ciphertext_block, key) ^ previous)
        previous = ciphertext_block
    return _pkcs7_unpad(_blocks_to_bytes(plaintext_blocks))


def tamper_ciphertext(ciphertext: bytes, block_index: int, xor_mask: int) -> bytes:
    """Return a copy with one CBC ciphertext block XOR-modified."""

    aligned = _require_block_aligned(ciphertext)
    if not isinstance(block_index, int) or isinstance(block_index, bool):
        raise TypeError("block_index must be an integer")
    if not 0 <= block_index < len(aligned) // 2:
        raise ValueError("block_index is outside the ciphertext")
    _validate_block(xor_mask, "xor_mask")
    blocks = [aligned[offset : offset + 2] for offset in range(0, len(aligned), 2)]
    original = int.from_bytes(blocks[block_index], "big")
    blocks[block_index] = (original ^ xor_mask).to_bytes(2, "big")
    return b"".join(blocks)


def double_encrypt(plaintext: int, key1: int, key2: int) -> int:
    """Two-key cascade: E_K2(E_K1(P))."""

    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt(ciphertext: int, key1: int, key2: int) -> int:
    """Inverse of :func:`double_encrypt`."""

    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def _normalize_triple_mode(mode: str) -> str:
    aliases = {
        "eee": "eee",
        "ede": "ede",
        "ede2": "ede2",
        "2-key-ede": "ede2",
        "2key-ede": "ede2",
    }
    try:
        return aliases[mode.lower().strip()]
    except (AttributeError, KeyError) as error:
        raise ValueError("mode must be one of eee, ede or ede2") from error


def triple_encrypt(plaintext: int, key1: int, key2: int, key3: int | None = None, mode: str = "ede") -> int:
    """Triple encryption in EEE, independent-key EDE, or two-key EDE2 mode."""

    normalized_mode = _normalize_triple_mode(mode)
    if normalized_mode == "ede2":
        first = encrypt_block(plaintext, key1)
        middle = decrypt_block(first, key2)
        return encrypt_block(middle, key1)
    if key3 is None:
        raise ValueError("key3 is required for a three-key triple mode")
    first = encrypt_block(plaintext, key1)
    if normalized_mode == "eee":
        middle = encrypt_block(first, key2)
    else:
        middle = decrypt_block(first, key2)
    return encrypt_block(middle, key3)


def triple_decrypt(ciphertext: int, key1: int, key2: int, key3: int | None = None, mode: str = "ede") -> int:
    """Inverse operation for :func:`triple_encrypt`."""

    normalized_mode = _normalize_triple_mode(mode)
    if normalized_mode == "ede2":
        first = decrypt_block(ciphertext, key1)
        middle = encrypt_block(first, key2)
        return decrypt_block(middle, key1)
    if key3 is None:
        raise ValueError("key3 is required for a three-key triple mode")
    first = decrypt_block(ciphertext, key3)
    if normalized_mode == "eee":
        middle = decrypt_block(first, key2)
    else:
        middle = encrypt_block(first, key2)
    return decrypt_block(middle, key1)


def _normalize_pairs(pairs: Iterable[KnownPair]) -> tuple[KnownPair, ...]:
    normalized: list[KnownPair] = []
    for plaintext, ciphertext in pairs:
        normalized.append((_validate_block(plaintext, "plaintext"), _validate_block(ciphertext, "ciphertext")))
    if not normalized:
        raise ValueError("at least one known plaintext/ciphertext pair is required")
    return tuple(normalized)


def meet_in_the_middle(
    pairs: Iterable[KnownPair],
    *,
    progress: ProgressCallback | None = None,
    max_results: int | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> list[tuple[int, int]]:
    """Find two-key cascade candidates with a meet-in-the-middle attack.

    For every possible K1, the function stores E_K1(P1).  It then computes
    D_K2(C1) for every possible K2 and joins equal intermediate values.  Every
    candidate is checked against all supplied pairs, so additional pairs can
    reduce false positives from a single pair.

    max_results must be None or a positive integer. Reaching this limit stops
    the search early, so the returned candidates may not be exhaustive.
    cancelled is an optional predicate; returning True raises CancelledError
    without returning a partial candidate list. Progress reports each phase
    up to its full key space when the search completes normally.
    """

    if max_results is not None:
        if isinstance(max_results, bool) or not isinstance(max_results, int):
            raise TypeError("max_results must be a positive integer or None")
        if max_results <= 0:
            raise ValueError("max_results must be a positive integer")
    known_pairs = _normalize_pairs(pairs)
    first_plaintext, _ = known_pairs[0]
    _, first_ciphertext = known_pairs[0]
    key_space = 1 << BLOCK_BITS
    forward: dict[int, list[int]] = {}

    for key1 in range(key_space):
        if cancelled is not None and cancelled():
            raise CancelledError("MITM search cancelled")
        intermediate = encrypt_block(first_plaintext, key1)
        forward.setdefault(intermediate, []).append(key1)
        if progress is not None and ((key1 + 1) % 4096 == 0):
            progress("forward", key1 + 1, key_space)

    candidates: list[tuple[int, int]] = []
    for key2 in range(key_space):
        if cancelled is not None and cancelled():
            raise CancelledError("MITM search cancelled")
        intermediate = decrypt_block(first_ciphertext, key2)
        for key1 in forward.get(intermediate, ()):
            if all(double_encrypt(plaintext, key1, key2) == ciphertext for plaintext, ciphertext in known_pairs):
                candidates.append((key1, key2))
                if max_results is not None and len(candidates) >= max_results:
                    if progress is not None:
                        progress("backward", key2 + 1, key_space)
                    return candidates
        if progress is not None and ((key2 + 1) % 4096 == 0):
            progress("backward", key2 + 1, key_space)
    return candidates
