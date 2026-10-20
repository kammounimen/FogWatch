#!/usr/bin/env python3
"""
distributed_attack.py : attaque distribuée discrète contre les 3 sites fog.

À lancer depuis la VM ATTAQUANTE (ni un des 3 sites, ni un nœud du cluster K3s, et son IP ne doit
PAS être dans l'ALLOWLIST des response-agents). Aucune dépendance : pas besoin de nmap.

Chaque tentative = une connexion TCP vers le port 22 puis fermeture immédiate. Suricata voit un SYN
par tentative (règle 9000001, flags:S), donc chaque site compte exactement N tentatives.
(nmap -p 22,80 n'enverrait qu'UN seul SYN vers le port 22 : un site compterait 1, pas 3.)

Exemples :
    python3 distributed_attack.py                       # 3 tentatives par site, pause de 5 s entre sites
    python3 distributed_attack.py --tentatives 2
    python3 distributed_attack.py --pause-sites 8 --window 30

IMPORTANT : l'agent garde les tentatives sur une fenêtre glissante de WINDOW_SECONDS (30 s).
Pour que le corrélateur voie les 3 sites en même temps, toute l'attaque doit tenir
largement dans cette fenêtre. Le script avertit si ce n'est pas le cas.
"""
import argparse
import socket
import time
from datetime import datetime, timezone

SITES = {
    "A": "100.103.105.18",
    "B": "100.75.234.57",
    "C": "100.78.123.31",
}


def stamp():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def attempt(ip, port, timeout):
    """Une tentative de connexion TCP (1 SYN). Retourne un court texte de résultat."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return "connexion ouverte puis fermée"
    except OSError as exc:
        return f"échec ({exc.__class__.__name__})"


def main():
    parser = argparse.ArgumentParser(description="Attaque distribuée discrète contre les sites fog")
    parser.add_argument("--tentatives", type=int, default=3, help="tentatives par site (3)")
    parser.add_argument("--pause-tentatives", type=float, default=1.0, help="secondes entre 2 tentatives (1)")
    parser.add_argument("--pause-sites", type=float, default=5.0, help="secondes entre 2 sites (5)")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--ordre", default="A,B,C", help="ordre des sites (A,B,C)")
    parser.add_argument("--window", type=float, default=30.0, help="WINDOW_SECONDS des agents (30)")
    args = parser.parse_args()

    ordre = [s.strip().upper() for s in args.ordre.split(",") if s.strip()]
    n = len(ordre)
    duree = (n - 1) * args.pause_sites + n * (args.tentatives - 1) * args.pause_tentatives
    print(f"[{stamp()}] Plan : {args.tentatives} tentatives sur {n} sites, durée totale environ {duree:.0f}s "
          f"(fenêtre des agents : {args.window:.0f}s)")
    if duree >= 0.8 * args.window:
        print("  /!\\ ATTENTION : l'attaque dure presque autant que la fenêtre. Les premières tentatives "
              "risquent de sortir de la fenêtre avant que le dernier site soit touché : le corrélateur "
              "ne verrait jamais les 3 sites en même temps. Réduis --pause-sites ou augmente WINDOW_SECONDS.")

    debut = time.time()
    for i, nom in enumerate(ordre):
        ip = SITES[nom]
        for k in range(1, args.tentatives + 1):
            resultat = attempt(ip, args.port, args.timeout)
            print(f"[{stamp()}] site {nom} ({ip}) tentative {k}/{args.tentatives} : {resultat}")
            if k < args.tentatives:
                time.sleep(args.pause_tentatives)
        if i < n - 1:
            time.sleep(args.pause_sites)

    print(f"[{stamp()}] Attaque distribuée terminée en {time.time() - debut:.1f}s "
          f"({args.tentatives * n} tentatives au total).")


if __name__ == "__main__":
    main()
