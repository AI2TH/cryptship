#!/usr/bin/env python3
"""A stand-in 'closed-source' app.

The point of the demo: this source — including SECRET_SAUCE and the
proprietary_algorithm body — must NOT appear in plaintext anywhere in the
shipped image. It only exists in cleartext inside the container at runtime,
after the loader has decrypted the payload with a valid license.
"""

SECRET_SAUCE = "the-answer-is-42-do-not-leak"


def proprietary_algorithm(x: int) -> int:
    # Pretend this is valuable IP worth protecting.
    return (x * 1337) ^ 0xC0FFEE


if __name__ == "__main__":
    print("cryptship demo app running")
    print("secret sauce :", SECRET_SAUCE)
    print("algo(7)      :", proprietary_algorithm(7))
