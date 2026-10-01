#!/usr/bin/env python3
"""Clean re-implementation of RenaultImmCode.exe.

The original is a 1997 Borland Pascal DOS tool ("Moulinette Codes Verlog
Version 7, 20/Aout/97") that turns the code printed on a Renault key tag into
the immobiliser security code ("Code Securite Antidemarrage").

Usage:
    renault_imm_code.py                      interactive, like the DOS program
    renault_imm_code.py VEHICLE KEYCODE      one-shot, e.g.  B56C  W12345
    renault_imm_code.py --debug VEHICLE KEYCODE

In interactive mode the password is TRANTIR, or TRANTIR++ for the hidden
debug trace.

Overview of the algorithm:
  * The vehicle type (e.g. "B56C", "VF1B56C") gives a vehicle generation
    (0, 1 or 2) that decides which of the two possible codes is shown.
  * The first letter of the key code selects the key family.  Each family
    decodes the key code to two bytes A and B ("OctA"/"OctB"), except for fixed
    code Valeo keys, which give the 4-digit code directly.
  * code 2 = (B*256 + A) mod 6561, written as 4 base-9 digits using 1..9.
    code 1 = low byte of (code2 value + 1), written as 4 base-4 digits
    using 1..4.
"""

from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field

HEX_DIGITS = "0123456789ABCDEF"
BUTTON_DIGITS = "123456789"  # 4-digit codes use '1'..'9', never '0'

# --- Key family tables --------------------------------------------------------

# 'W' keys (TIR TRW X06): each of the 6 characters encodes one hex digit.
# Position i maps W_ALPHABETS[i][n] -> hex digit n.
W_ALPHABETS = (
    "KLNPSTUXYZBCDGHJ",
    "PSTUWYZACDEHJKLM",
    "DEGJKLMNSTUWXZAB",
    "UWXYABCEGHKLMNPT",
    "XYZBCDGHJLMNPSUW",
)
# The last character only carries even hex digits, two letters per value.
W_LAST_PAIRS = ("AZ", "CD", "EH", "JK", "MN", "PS", "TW", "XY")

# 'P'/'V'/'R' keys (TIR Valeo, rolling code): plain hex, 'O' and 'I' are
# accepted and corrected to '0' and '1'.
PVR_CHARSET = set(HEX_DIGITS + "IO")

# 'Y'/'Z'/'F' keys (Siemens and Valeo transponders): 7 base-32 digits.
YZF_ALPHABET = "XWURMGA3PC0ET7FKVSNH819JLB2Q4D56"
YZF_CORRECTIONS = {"O": "0", "I": "1"}
YZF_FIRST_CHARS = "RUWX"  # first digit is 0..3, so the value fits in 32 bits

# 'E'/'A' keys (X65/X76/X70 transponders): 6 base-32 digits, each position
# using the base alphabet rotated by 9 more places, plus one final 2-bit digit.
EA_ALPHABET = "259CFJMPTWZ36ADGKNRUX147BEHLQSVY"
EA_LAST_GROUPS = ("36ADGKNZ", "147BERUX", "25HLQSVY", "9CFJMPTW")
EA_CORRECTIONS = {"O": "Q", "0": "Q", "8": "B", "I": "1"}

# 'S' keys (TIR Siemens X64): 4 characters, each one hex digit.
S_ALPHABET = "987654321TLUANER"

# Key codes made of digits (TIR Valeo, fixed code).
VALEO_FIXED_VALUES = {"8": 0, "2": 1, "5": 2, "6": 4, "0": 5, "3": 6, "7": 8, "1": 9, "4": 10}
VALEO_FIXED_CORRECTIONS = {"O": "0"}

KEY_LABELS = {
    "W": "CLE TIR TRW X06",
    "V": "CLE TIR VALEO CODE EVOLUTIF",
    "P": "CLE TIR VALEO CODE EVOLUTIF",
    "R": "CLE TIR VALEO CODE EVOLUTIF",
    "Z": "CLE TIR+TRanspondeur VALEO",
    "F": "CLE TRF+TRanspondeur VALEO",
    "Y": "CLE TRANSPONDEUR SIEMENS",
    "S": "CLE TIR SIEMENS X64",
    "E": "CLE TRANSPONDEUR X65/X76/X70",
    "A": "CLE TRANSPONDEUR X65/X76/X70",
}
DEFAULT_KEY_LABEL = "CLE TIR VALEO CODE FIXE"

# Which code(s) to show, by (vehicle generation, key version).
# Key version 0 means the key yields both codes.
BOTH, CODE1, CODE2, INCOHERENT = "both", "code1", "code2", "incoherent"
DISPLAY = {
    (0, 0): BOTH, (0, 1): CODE1, (0, 2): CODE2,
    (1, 0): CODE1, (1, 1): CODE1, (1, 2): CODE2,
    (2, 0): CODE2, (2, 1): INCOHERENT, (2, 2): CODE2,
}

MAX_INPUT = 10  # the original reads into string[10]
PASSWORD = "TRANTIR"
DEBUG_PASSWORD = PASSWORD + "++"
PASSWORD_ATTEMPTS = 3


# --- Small helpers ------------------------------------------------------------

def upcase(text: str) -> str:
    """Pascal UpCase: only ASCII a..z change."""
    return "".join(chr(ord(c) - 32) if "a" <= c <= "z" else c for c in text)


def bit_reverse(byte: int) -> int:
    return int(f"{byte:08b}"[::-1], 2)


def byte_to_hex(value: int) -> str:
    return f"{value & 0xFF:02X}"


def word_to_hex(value: int) -> str:
    return f"{value & 0xFFFF:04X}"


def hex_to_byte(text: str) -> int:
    """Two hex digits to a byte. An invalid digit counts as -1, as in the original."""
    hi, lo = (HEX_DIGITS.find(text[i]) if i < len(text) else -1 for i in range(2))
    return (hi * 16 + lo) & 0xFF


def button_code(value: int, base: int) -> str:
    """4 digits in the given base, written with '1'..'9' instead of '0'..'8'."""
    digits = []
    for _ in range(4):
        value, digit = divmod(value, base)
        digits.append(BUTTON_DIGITS[digit])
    return "".join(reversed(digits))


def length_error(text: str, expected: int) -> int:
    return (len(text) > expected) - (len(text) < expected)


def tp_real(value: float) -> str:
    """Turbo Pascal Write(real:17): ' d.ddddddddddE+XX'."""
    mantissa, exponent = f"{value:.10E}".split("E")
    sign = "-" if mantissa.startswith("-") else " "
    return f"{sign}{mantissa.lstrip('-')}E{int(exponent):+03d}"


def code1_from(value: int) -> str:
    """Code 1: the low byte of value (0 and 255 replaced by high byte + 1), in base 4."""
    low = value & 0xFF
    if low in (0, 0xFF):
        low = (value >> 8) + 1
    return button_code(low, 4)


# --- Vehicle type -------------------------------------------------------------

@dataclass
class Vehicle:
    generation: int  # 0, 1 or 2 ("VehV1ouV2")
    typveh: str      # vehicle type, 2 chars (e.g. "56")
    tytmot: str      # 1st and 4th char of the type


def classify_vehicle(vehicle: str) -> Vehicle:
    s = vehicle
    if s.startswith("V"):
        s = s[1:]
        if s.startswith("F"):
            s = s[1:]
    if s.startswith("1"):
        s = s[1:]
    if s.startswith("8"):
        s = s[1:]
    s = s[:4]
    typveh = s[1:3]
    # The original reads s[4] even when the type is shorter (garbage memory).
    fourth = s[3] if len(s) >= 4 else " "
    tytmot = s[:1] + fourth

    typveh = {"O6": "06", "AO": "A0", "64": "A0", "EO": "E0", "66": "E0",
              "DO": "D0", "70": "D0"}.get(typveh, typveh)

    generation = 0
    if typveh in ("06", "A0", "E0"):
        generation = 2
    elif typveh == "53":
        generation = 1
    elif typveh == "56":
        generation = 1 if fourth in "ABCDESHNRZ7" else 2
    elif typveh == "54":
        generation = 1 if fourth in "012345EHJBOI" else 2
    elif typveh == "57":
        generation = 1
        if tytmot in ("3N", "5N", "3M", "5M", "3Y", "5Y", "3K", "5K") or fourth in "L67":
            generation = 2
    elif typveh == "63":
        generation = 2 if fourth in "DE3" else 1
    return Vehicle(generation, typveh, tytmot)


# --- Key decoding -------------------------------------------------------------

@dataclass
class Evaluation:
    vehicle: Vehicle
    key: str                  # key code after the D0 tweak
    family: str               # first letter of the key code
    key_version: int = 0      # 0: both codes, 1: code 1 only, 2: code 2 only
    length_error: int = 0     # +1 too many characters, -1 not enough
    bad_char: bool = False
    corrected: bool = False
    octets: tuple[int, int] = (0, 0)   # (OctA, OctB)
    plip_octets: tuple[int, int] = (0, 0)
    code1: str = ""
    code2: str = ""
    security_zero: str = ""   # extra "0xxx" code for some X65/X76/X70 keys
    plip: str = ""            # "Special Resynchro Plip" code (some 'Z' keys)
    trace: list[str] = field(default_factory=list)  # debug output

    @property
    def ok(self) -> bool:
        return not self.length_error and not self.bad_char

    @property
    def label(self) -> str:
        return KEY_LABELS.get(self.family, DEFAULT_KEY_LABEL)


def _lookup(ev: Evaluation, table: dict[str, int], corrections: dict[str, str],
            text: str, index: int) -> int | None:
    """Look up text[index], applying character corrections and flagging errors."""
    char = text[index] if index < len(text) else ""
    if char in corrections:
        char = corrections[char]
        ev.corrected = True
    value = table.get(char)
    if value is None:
        ev.bad_char = True
    return value


def _fmt(value: int | None) -> str:
    return "?" if value is None else str(value)


def _octets_from_hex(ev: Evaluation, hexcode: str, names: tuple[str, ...]) -> list[int]:
    octets = []
    for i, name in enumerate(names):
        pair = hexcode[2 * i:2 * i + 2]
        ev.trace.append(f"   {name} : {pair}")
        octets.append(hex_to_byte(pair))
    return octets


def _decode_w(ev: Evaluation, body: str) -> None:
    tables = [{c: HEX_DIGITS[n] for n, c in enumerate(a)} for a in W_ALPHABETS]
    tables.append({c: HEX_DIGITS[2 * n] for n, pair in enumerate(W_LAST_PAIRS) for c in pair})
    ev.length_error = length_error(body, 6)
    hexcode = ""
    for i, table in enumerate(tables):
        digit = table.get(body[i]) if i < len(body) else None
        if digit is None:
            ev.bad_char = True
            digit = "?"
        hexcode += digit
        ev.trace.append(digit)
    ev.trace.append(hexcode + "\n")
    oct3, oct2, oct1 = _octets_from_hex(ev, hexcode, ("Oct3", "Oct2", "Oct1"))
    a = oct2 ^ oct1
    ev.octets = (a, oct3 ^ a)
    ev.key_version = 2


def _decode_pvr(ev: Evaluation, body: str) -> None:
    ev.length_error = length_error(body, 6)
    if sum(c in PVR_CHARSET for c in body) < len(body):
        ev.bad_char = True
    if "O" in body or "I" in body:
        ev.corrected = True
        body = body.replace("O", "0").replace("I", "1")
    ev.trace.append(body + "\n")
    oct3, oct2, oct1 = _octets_from_hex(ev, body, ("Oct3", "Oct2", "Oct1"))
    a = oct2 ^ oct1
    ev.octets = (a, oct3 ^ a)
    ev.key_version = 0


def _decode_yzf(ev: Evaluation, body: str) -> None:
    ev.length_error = length_error(body, 7)
    ev.bad_char = not body or body[0] not in YZF_FIRST_CHARS
    table = {c: n for n, c in enumerate(YZF_ALPHABET)}
    digits = [_lookup(ev, table, YZF_CORRECTIONS, body, i) for i in range(7)]
    ev.trace.append("KCode:   " + " ".join(map(_fmt, digits)) + "\n")
    if ev.bad_char:
        return

    value = 0
    for digit in digits:
        value = value * 32 + digit
    ev.trace.append("Refcle:" + tp_real(value) + "\n")
    r0, r1, r2, r3 = value.to_bytes(4, "big")
    ev.trace.append(" Ref Cle:  " + " ".join(map(byte_to_hex, (r0, r1, r2, r3))) + "\n")

    # The high nibble of the first byte is replaced by a checksum nibble.
    total = (r0 + r1 + r2 + r3) & 0xFF
    checksum = ((total >> 4) + (total & 0x0F)) & 0x0F
    rta = (checksum << 4) | (r0 & 0x0F)
    ev.trace.append(f"RTA:   {rta}   {r1}   {r2}  {r3}\n")

    for byte in (r3, r2, r1, rta):  # the bit-reverse routine dumps its input bits
        ev.trace.append("  " + " ".join(f"{byte:08b}") + "\n")
    k = (bit_reverse(r3) ^ 0xC5, bit_reverse(r2) ^ 0x71,
         bit_reverse(r1) ^ 0x31, bit_reverse(rta) ^ 0x17)
    ev.trace.append(f"Code cle dec:   {k[0]}   {k[1]}   {k[2]}  {k[3]}\n")
    ev.trace.append("Code Cle hexa : " + " ".join(map(byte_to_hex, k)) + "\n")

    ev.octets = (k[2] ^ k[3], k[1] ^ k[0])
    plip_a = (k[3] ^ 0xF0) ^ (k[2] ^ 0x55)
    ev.plip_octets = (plip_a, (k[1] ^ 0xAA) ^ plip_a)
    ev.key_version = 0 if ev.family == "Y" else 2


def _decode_ea(ev: Evaluation, body: str) -> None:
    ev.length_error = length_error(body, 7)
    tables = [{c: (n + 9 * pos) % 32 for n, c in enumerate(EA_ALPHABET)} for pos in range(6)]
    tables.append({c: n for n, group in enumerate(EA_LAST_GROUPS) for c in group})
    digits = [_lookup(ev, table, EA_CORRECTIONS, body, i) for i, table in enumerate(tables)]
    ev.trace.append("KCode:   " + " ".join(map(_fmt, digits)) + "\n")
    if ev.bad_char:
        return

    value = 0
    for digit in digits[:6]:
        value = value * 32 + digit
    value = value * 4 + digits[6]
    ev.trace.append("Refcle:" + tp_real(value) + "\n")
    r = value.to_bytes(4, "big")
    ev.trace.append(f"Code cle dec:   {r[0]}   {r[1]}   {r[2]}  {r[3]}\n")
    ev.trace.append("Code Cle hexa : " + " ".join(map(byte_to_hex, r)) + "\n")
    ev.octets = (r[2] ^ r[3], r[1] ^ r[0])
    ev.key_version = 2


def _decode_s(ev: Evaluation, body: str) -> None:
    ev.length_error = length_error(body, 4)
    table = {c: HEX_DIGITS[n] for n, c in enumerate(S_ALPHABET)}
    hexcode = ""
    for i in range(4):
        digit = table.get(body[i]) if i < len(body) else None
        if digit is None:
            ev.bad_char = True
            digit = "?"
        hexcode += digit
        ev.trace.append(digit)
    oct2, oct1 = _octets_from_hex(ev, hexcode, ("Oct2", "Oct1"))
    a = oct2 ^ 0x3A
    ev.octets = (a, a ^ oct1)
    ev.key_version = 2


def _decode_valeo_fixed(ev: Evaluation, code: str) -> None:
    # An 8 character code with a letter in 7th position keeps only 5 chars.
    if len(code) == 8 and "A" <= code[6] <= "Z":
        code = code[:5]
    ev.length_error = length_error(code, 5)

    def nibble(i: int) -> int:
        value = _lookup(ev, VALEO_FIXED_VALUES, VALEO_FIXED_CORRECTIONS, code, i)
        return 0 if value is None else value

    b1 = (nibble(4) + 0xE0) & 0xFF
    b2 = (nibble(2) + (nibble(3) << 4)) & 0xFF
    b3 = (nibble(0) + (nibble(1) << 4)) & 0xFF
    ev.trace.append(f"   B1 : {b1}   B2 : {b2}   B3 : {b3}\n")

    cvl1 = (b3 + b2) % 256
    ev.trace.append(f"CVL1Dec  : {cvl1}    CVL1hexa: {word_to_hex(cvl1)}\n")
    if cvl1 == 0:
        cvl1 = b1
    if cvl1 == 0xFF:
        cvl1 = b2 - 1
    ev.code1 = button_code(cvl1, 4)
    ev.key_version = 1


def evaluate(vehicle: str, key: str, previous_octets: tuple[int, int] = (0, 0)) -> Evaluation:
    """Compute everything the original prints for one vehicle type/key code pair.

    Pass back the octets of the previous Evaluation to reproduce the debug
    trace of the original (fixed-code keys print a CVL2 line built from the
    previous key's leftover octets).
    """
    vehicle = upcase(vehicle)[:MAX_INPUT]
    key = upcase(key)[:MAX_INPUT]
    veh = classify_vehicle(vehicle)
    if len(key) == 7 and veh.typveh == "D0":
        key = "E" + key

    ev = Evaluation(vehicle=veh, key=key, family=key[:1], octets=previous_octets)
    body = key[1:]
    if ev.family == "W":
        _decode_w(ev, body)
    elif ev.family in ("P", "V", "R"):
        _decode_pvr(ev, body)
    elif ev.family in ("Y", "Z", "F"):
        _decode_yzf(ev, body)
    elif ev.family in ("E", "A"):
        _decode_ea(ev, body)
    elif ev.family == "S":
        _decode_s(ev, body)
    else:
        _decode_valeo_fixed(ev, key)

    if not ev.ok:
        return ev

    a, b = ev.octets
    ev.trace.append(f"     OctB= {byte_to_hex(b)}    OctA= {byte_to_hex(a)}")
    cvl2 = (b << 8 | a) % 6561 + 1
    ev.trace.append(f"CVL2Dec  : {cvl2}    CVL2hexa: {word_to_hex(cvl2)}\n")
    ev.code2 = button_code(cvl2 - 1, 9)
    if ev.family == "E" and ev.code2.startswith("1"):
        ev.security_zero = "0" + ev.code2[1:]

    if ev.family == "Z":
        plip_a, plip_b = ev.plip_octets
        plip_value = (plip_b << 8 | plip_a) % 6561
        if veh.typveh == "E0":
            ev.plip = button_code(plip_value, 9)
        elif veh.typveh == "54":
            ev.plip = code1_from(plip_value + 1)
            ev.trace.append(_cvl1_trace(plip_value + 1))

    if ev.key_version == 0:
        ev.code1 = code1_from(cvl2)
        ev.trace.append(_cvl1_trace(cvl2))
    return ev


def _cvl1_trace(value: int) -> str:
    low = value & 0xFF
    if low in (0, 0xFF):
        low = (value >> 8) + 1
    return f"CVL1Dec  : {low}    CVL1hexa: {word_to_hex(low)}\n"


# --- Output -------------------------------------------------------------------

RED, RESET = "\033[31m", "\033[0m"
MARGIN = " " * 32


def result_lines(ev: Evaluation) -> list[str]:
    """The lines inside the RESULTAT box (the original prints them in red)."""
    def boxed(text: str) -> str:
        return f"{MARGIN}│{text}│"

    lines = []
    if ev.security_zero:
        lines.append(boxed(f"   Code Securite Antidemarrage : {ev.security_zero}  "))
    shown = DISPLAY[(ev.vehicle.generation, ev.key_version)]
    if shown == BOTH:
        lines.append(boxed(f"  Code Securite Antidemarrage1 : {ev.code1}  "))
        lines.append(boxed(f"  Code Securite Antidemarrage2 : {ev.code2}  "))
    elif shown == INCOHERENT:
        lines.append(boxed("** Incoherent DATA : cannot process ** "))
    else:
        code = ev.code1 if shown == CODE1 else ev.code2
        lines.append(boxed(f"   Code Securite Antidemarrage : {code}  "))
    return lines


def render(ev: Evaluation, debug: bool, color: bool) -> str:
    out = []
    if debug:
        out.extend(ev.trace)
    if ev.length_error > 0:
        out.append(" ***** attention : trop de caracteres  *****\n")
        out.append(" *****  warning : too many characters  *****\n")
    if ev.length_error < 0:
        out.append(" ***** attention : pas assez de caracteres  *****\n")
        out.append(" ******  warning  : not enough characters   *****\n")
    if ev.bad_char:
        out.append(" ***** caractere incorrect dans code  *****\n")
        out.append(" ***** incorrect character in code  *****\n")
    if debug:
        veh = ev.vehicle
        out.append(f" TYPVEH:{veh.typveh} TYTMOT:{veh.tytmot}"
                   f"    VehV1ouV2 :{veh.generation}    KeyV1ouV2 :{ev.key_version}\n")
    if not ev.ok:
        return "".join(out)

    if debug:
        if ev.corrected:
            out.append(" ***** caractere corrige  *****\n")
            out.append(" ***** character corrected  *****\n")
        out.append(f" ({ev.label})")
    out.append(f"{MARGIN}┌------------ RESULTAT -----------------┐\n")
    for line in result_lines(ev):
        out.append(f"{RED}{line}{RESET}\n" if color else line + "\n")
    if ev.plip:
        out.append(f"{MARGIN}│  (Special Resynchro Plip : {ev.plip})      │\n")
    return "".join(out)


# --- Interactive program ------------------------------------------------------

def _read_key() -> str:
    """Read one keypress without echo, or '' at end of input."""
    try:
        import msvcrt
        return msvcrt.getwch()
    except ImportError:
        pass
    import termios
    import tty
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def _stars() -> None:
    # The original echoes 1 to 3 random stars per key to hide the length.
    sys.stdout.write("*" * random.randint(1, 3))
    sys.stdout.flush()


def read_password() -> str | None:
    """Masked password entry; None means quit (Esc, Ctrl-C or end of input)."""
    if not sys.stdin.isatty():
        line = sys.stdin.readline()
        if not line:
            return None
        line = line.rstrip("\r\n")
        for _ in range(len(line) + 1):
            _stars()
        return line

    password = ""
    while True:
        key = _read_key()
        if key in ("", "\x03", "\x1b"):
            return None
        if key in ("\r", "\n"):
            _stars()
            return password
        if key in ("\b", "\x7f"):
            password = password[:-1]
        elif len(password) < MAX_INPUT:
            password += key
        _stars()


def login() -> bool | None:
    """Ask for the password. Returns the debug flag, or None to quit."""
    for _ in range(PASSWORD_ATTEMPTS):
        print()
        print(" Enter Password : ")
        password = read_password()
        if not password:
            return None
        password = upcase(password)
        if password in (PASSWORD, DEBUG_PASSWORD):
            print("*** Moulinette Codes Verlog Version 7  20/Aout/97 ********")
            return password == DEBUG_PASSWORD
    return None


def ask(prompt: str) -> str | None:
    try:
        answer = input(prompt)
    except EOFError:
        return None
    if not sys.stdin.isatty():
        print(answer)  # keep a readable transcript when input is piped
    return answer[:MAX_INPUT]


def interactive(color: bool) -> int:
    debug = login()
    if debug is None:
        return 0
    octets = (0, 0)
    while True:
        print("=" * 79)
        vehicle = ask("Enter Vehicle type (ex B56C) : ")
        key = ask("Enter Key Code               : ") if vehicle is not None else None
        if not key:
            return 0
        ev = evaluate(vehicle, key, octets)
        octets = ev.octets
        sys.stdout.write(render(ev, debug, color))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("vehicle", nargs="?", help="vehicle type, e.g. B56C")
    parser.add_argument("key", nargs="?", help="key code from the key tag")
    parser.add_argument("--debug", action="store_true", help="print the intermediate values")
    parser.add_argument("--no-color", action="store_true", help="never use ANSI colours")
    args = parser.parse_args(argv)
    color = sys.stdout.isatty() and not args.no_color

    if args.vehicle is None:
        return interactive(color)
    if args.key is None:
        parser.error("give both VEHICLE and KEYCODE, or neither for interactive mode")
    ev = evaluate(args.vehicle, args.key)
    sys.stdout.write(render(ev, args.debug, color))
    return 0 if ev.ok else 1


if __name__ == "__main__":
    sys.exit(main())
