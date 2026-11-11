Group Dasalla
11/6/2026
DES algorithm for AIS Case Study 

# Modified DES with CBC and HMAC-SHA256

This study adds rotation and XOR mixing after the DES P-box to spread bit changes earlier. CBC encrypts full messages; HMAC-SHA256 checks for changes before decryption. `des.py` is the standard DES comparison, while `modified_des.py` is used by the prototype.

## Run the prototype

Keep `main.py`, `authenticated_des.py`, `modified_des.py`, and `des.py` in one folder. With Python 3 installed, run `python main.py` (or `py main.py` on Windows).

- Choose **1** to encrypt a message (up to 255 characters). Enter a 16-digit hex DES key or press Enter to generate one.
- Save the **full packet**, **DES key**, and **HMAC key** shown. Choose **2** and enter those same values to decrypt.

The full packet contains the IV, ciphertext, and HMAC tag. Successful decryption shows `Authentication: Passed` and the message. If the packet or HMAC key changed, it shows `Error: Authentication failed` and does not decrypt. The encryption screen also demonstrates this rejection by changing one bit in a copy of the packet.

To reproduce the study checks, run `python test.py` for standard versus modified DES avalanche and timing, and `python test_authenticated_des.py` for message recovery and tamper checks.