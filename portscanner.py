import socket
import requests
from urllib.parse import urljoin

from Wappalyzer import Wappalyzer, WebPage  # biblioteca python-Wappalyzer

#Configurações
COMMON_PATHS = ["/admin", "/login", "/phpmyadmin", "/robots.txt"]
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 5000]



KNOWN_CVES = {
    "Apache/2.4.49": "CVE-2021-41773 (Path Traversal / RCE em Apache 2.4.49)",
    "Apache/2.4.50": "CVE-2021-42013 (Bypass da correção do 41773)",
    "nginx/1.18.0": "CVE-2021-23017 (Heap buffer overflow em nginx resolver)",
    "OpenSSL/1.0.1": "CVE-2014-0160 (Heartbleed vulnerability)",
    "PHP/5.4": "CVE-2019-11043 (PHP-FPM RCE em versões antigas de PHP-FPM)"
}


def check_ports(host, ports):
    print("[*] Escaneando portas...")
    open_ports = []
    for port in ports:
        try:
            s = socket.create_connection((host, port), timeout=2)
            print(f"[+] Porta aberta: {port}")
            open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def check_http_headers(url):
    print("\n[*] Checando headers HTTP...")
    try:
        r = requests.get(url, timeout=5, verify=False)
        headers = r.headers

        print(f"[+] Status Code: {r.status_code}")
        if "Server" in headers:
            print(f"[+] Server: {headers['Server']}")
            check_cves(headers["Server"])
        if "X-Powered-By" in headers:
            print(f"[!] X-Powered-By detectado: {headers['X-Powered-By']}")
            check_cves(headers["X-Powered-By"])

        if "Content-Security-Policy" not in headers:
            print("[!] Sem Content-Security-Policy (risco de XSS)")
        if "X-Frame-Options" not in headers:
            print("[!] Sem X-Frame-Options (risco de Clickjacking)")
        if "Strict-Transport-Security" not in headers:
            print("[!] Sem HSTS (risco downgrade HTTP)")

    except Exception as e:
        print(f"[-] Erro ao requisitar {url} -> {e}")


def check_common_paths(url):
    print("\n[*] Procurando paths comuns...")
    for path in COMMON_PATHS:
        full_url = urljoin(url, path)
        try:
            r = requests.get(full_url, timeout=5, verify=False)
            if r.status_code == 200:
                print(f"[+] Path encontrado: {full_url}")
            elif r.status_code == 403:
                print(f"[!] Path protegido (403): {full_url}")
        except Exception as e:
            pass


def check_cves(tech_info):
    """CVEs conhecidos relacionados à versão detectada"""
    for signature, cve in KNOWN_CVES.items():
        if signature.lower() in tech_info.lower():
            print(f"[!!!] Vulnerável conhecido detectado: {cve}")


def detect_technologies_wappalyzer(url):
    #usando wappalyzer para detectar tecnologias do site"""
    print("\n[*] Detectando tecnologias com Wappalyzer...")
    try:
        wapp = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url, verify=False)
        techs = wapp.analyze_with_versions_and_categories(webpage)
        if techs:
            #fixar depois, lógica tá meio errada pra pegar a versão da tecnologia
            print("[+] Tecnologias detectadas:")
            for tech_name, info in techs.items():
                versions = info.get("versions", [])
                categories = info.get("categories", [])
                vs = ", ".join(versions) if versions else "versão não detectada"
                cs = ", ".join(categories) if categories else "categoria não detectada"
                print(f"   - {tech_name} | Versão(s): {vs} | Categorias: {cs}")
        else:
            print("[!] Nenhuma tecnologia detectada pelo Wappalyzer.")
    except Exception as e:
        print(f"[-] Erro durante detecção de tecnologias: {e}")


def main():
    print("=== Mini Web Vulnerability Scanner com Wappalyzer ===")
    target = input("Digite a URL alvo (ex: http://testphp.vulnweb.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    host = target.replace("http://", "").replace("https://", "").split("/")[0]

    #port Scan
    open_ports = check_ports(host, WEB_PORTS)

    #se achou porta web comum, prosseguir
    if any(p in WEB_PORTS for p in open_ports):
        detect_technologies_wappalyzer(target)
        check_http_headers(target)
        check_common_paths(target)
    else:
        print("[-] Nenhuma porta web comum encontrada.")


if __name__ == "__main__":
    main()



#Se ler direitinho o código é bem simples, eu só queria ter algumas ferramentas pra começar a fazer uns pentests web.
#Futuramente quero adicionar mais funcionalidades, como brute force de login, análise de formulários, etc.
#Mas isso fica pra depois. Por enquanto, tá aí um scanner web básico com Wappalyzer integrado.
#Meu sonho nesse código é fazer um loader de scripts, pra poder adicionar módulos depois, tipo o Metasploit.
#Estudando pra isso. (Quem sabe no próximo commit eu já não tenha conseguido fazer isso, né?
#Ah, e se alguém souber como pegar a versão exata das tecnologias detectadas pelo Wappalyzer, me avisa. Tá meio zoado isso aí.