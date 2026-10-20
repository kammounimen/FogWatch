#!/usr/bin/env python3
"""
distributed_scan.py
Simule une attaque distribuée en scannant les 3 sites fog l'un après l'autre,
avec un délai entre chaque pour imiter un comportement discret.

À lancer depuis la VM attaquante (pas un des 3 sites, pas dans le cluster K3s).
Nécessite nmap installé : sudo apt install -y nmap
"""

import subprocess
import time

SITES = [
    "100.103.105.18",  # site A
    "100.75.234.57",   # site B
    "100.78.123.31",   # site C
]

DELAI_ENTRE_SITES = 15  # secondes

def scanner(site):
    print(f"[+] Scan de {site} ...")
    subprocess.run(["nmap", "-p", "22,80", site])

def main():
    for site in SITES:
        scanner(site)
        print(f"[.] Pause de {DELAI_ENTRE_SITES}s avant le site suivant\n")
        time.sleep(DELAI_ENTRE_SITES)
    print("[OK] Attaque distribuée terminée sur les 3 sites.")

if __name__ == "__main__":
    main()
