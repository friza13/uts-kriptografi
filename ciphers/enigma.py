"""
Enigma M3 Cipher Machine Implementation.
Features:
- Rotors I, II, III (plus IV, V) with authentic historical wirings and turnover notches.
- Double-stepping mechanism of the middle rotor (historical M3 mechanism).
- Reflectors B and C.
- Steckerbrett (Plugboard) for arbitrary letter substitutions.
- Ringstellung (Ring settings) and Grundstellung (Initial positions).
- Inherent reciprocal encryption/decryption property.
"""

import re
from typing import List, Union, Dict


ROTOR_WIRINGS = {
    "I": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
    "II": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
    "III": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
    "IV": "ESOVPZJAYQUIRHXLNFTGKDCMWB",
    "V": "VZBRGITYUPSDNHLXAWMJQOFECK",
}

ROTOR_NOTCHES = {
    "I": 16,   # Q
    "II": 4,   # E
    "III": 21, # V
    "IV": 9,   # J
    "V": 25,   # Z
}

REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}


def _clean_alphabet(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", text).upper()


class Rotor:
    def __init__(self, wiring: str, notch: int, ring_setting: int = 0, initial_position: int = 0):
        self.wiring = [ord(c) - ord("A") for c in wiring]
        self.inv_wiring = [0] * 26
        for i, val in enumerate(self.wiring):
            self.inv_wiring[val] = i

        self.notch = notch
        self.ring_setting = ring_setting % 26
        self.position = initial_position % 26

    def is_at_notch(self) -> bool:
        return self.position == self.notch

    def step(self):
        self.position = (self.position + 1) % 26

    def forward(self, char_code: int) -> int:
        offset = (self.position - self.ring_setting) % 26
        internal = (char_code + offset) % 26
        wired = self.wiring[internal]
        return (wired - offset) % 26

    def backward(self, char_code: int) -> int:
        offset = (self.position - self.ring_setting) % 26
        internal = (char_code + offset) % 26
        wired = self.inv_wiring[internal]
        return (wired - offset) % 26


class Plugboard:
    def __init__(self, mapping_str: str = ""):
        self.mapping = list(range(26))
        if mapping_str:
            pairs = re.findall(r"[A-Za-z]{2}", mapping_str.upper())
            for pair in pairs:
                a = ord(pair[0]) - ord("A")
                b = ord(pair[1]) - ord("A")
                self.mapping[a] = b
                self.mapping[b] = a

    def swap(self, char_code: int) -> int:
        return self.mapping[char_code]


class EnigmaM3:
    """Enigma M3 Machine Simulator with 3 Rotors, Reflector, and Plugboard."""

    def __init__(
        self,
        rotors: List[str] = None,
        reflector: str = "B",
        ring_settings: List[int] = None,
        initial_positions: List[Union[int, str]] = None,
        plugboard: str = "",
    ):
        if rotors is None:
            rotors = ["I", "II", "III"]
        if ring_settings is None:
            ring_settings = [0, 0, 0]
        if initial_positions is None:
            initial_positions = [0, 0, 0]

        # Convert letter initial positions to ints if string
        clean_positions = []
        for p in initial_positions:
            if isinstance(p, str):
                clean_positions.append(ord(p.upper()) - ord("A"))
            else:
                clean_positions.append(int(p))

        self.rotors = [
            Rotor(
                wiring=ROTOR_WIRINGS[r],
                notch=ROTOR_NOTCHES[r],
                ring_setting=ring_settings[idx],
                initial_position=clean_positions[idx],
            )
            for idx, r in enumerate(rotors)
        ]

        # Rotors ordered: [0]=Left (Slow), [1]=Middle, [2]=Right (Fast)
        self.reflector_wiring = [ord(c) - ord("A") for c in REFLECTORS.get(reflector, REFLECTORS["B"])]
        self.plugboard = Plugboard(plugboard)

    def _step_rotors(self):
        # Enigma M3 double-stepping
        left_rotor = self.rotors[0]
        mid_rotor = self.rotors[1]
        right_rotor = self.rotors[2]

        mid_at_notch = mid_rotor.is_at_notch()
        right_at_notch = right_rotor.is_at_notch()

        if mid_at_notch:
            mid_rotor.step()
            left_rotor.step()
        elif right_at_notch:
            mid_rotor.step()

        right_rotor.step()

    def process_char(self, char: str) -> str:
        if not char.isalpha():
            return ""

        c_code = ord(char.upper()) - ord("A")
        self._step_rotors()

        # 1. Plugboard in
        c_code = self.plugboard.swap(c_code)

        # 2. Forward through rotors (Right -> Middle -> Left)
        c_code = self.rotors[2].forward(c_code)
        c_code = self.rotors[1].forward(c_code)
        c_code = self.rotors[0].forward(c_code)

        # 3. Reflector
        c_code = self.reflector_wiring[c_code]

        # 4. Backward through rotors (Left -> Middle -> Right)
        c_code = self.rotors[0].backward(c_code)
        c_code = self.rotors[1].backward(c_code)
        c_code = self.rotors[2].backward(c_code)

        # 5. Plugboard out
        c_code = self.plugboard.swap(c_code)

        return chr(c_code + ord("A"))

    def process_text(self, text: str) -> str:
        clean = _clean_alphabet(text)
        return "".join(self.process_char(c) for c in clean)

    def encrypt(self, text: str) -> str:
        return self.process_text(text)

    def decrypt(self, text: str) -> str:
        return self.process_text(text)
