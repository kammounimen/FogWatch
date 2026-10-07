import subprocess

ALLOWLIST = ["100.64.0.1", "100.64.0.2", "100.64.0.3"]

def block_ip(ip):
    if ip in ALLOWLIST:
        print(f"IP {ip} dans la allowlist, pas de blocage")
        return
    subprocess.run([
        "sudo", "nft", "add", "rule", "inet", "filter", "input",
        "ip", "saddr", ip, "drop"
    ])
    print(f"IP {ip} bloquée")

if __name__ == "__main__":
    test_ip = input("IP à bloquer (test) : ")
    block_ip(test_ip)
