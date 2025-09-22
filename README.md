# 🕷️ Mini Web Vulnerability Scanner

Este é um **scanner web educacional em Python**, desenvolvido para estudo de segurança ofensiva (**Red Team**).  
Ele realiza detecção de portas abertas, coleta de headers HTTP, enumeração de paths comuns e identificação de tecnologias com **Wappalyzer**, além de associar riscos de segurança a cada achado.

⚠️ **Aviso importante**: este projeto é apenas para **uso em laboratório controlado** (como DVWA, OWASP Juice Shop, Metasploitable).  
**Nunca utilize em sistemas sem permissão explícita.**

---

## 🚀 Funcionalidades
- 🔎 **Port Scan** em portas web comuns (80, 443, 8080, 8443, etc).  
- 📡 **Coleta de Headers HTTP** e checagem de segurança.  
- 🗂️ **Enumeração de paths comuns** como `/admin`, `/login`, `/phpmyadmin`.  
- 🧩 **Detecção de tecnologias** (frameworks, servidores, CMS) com **Wappalyzer**.  
- 📜 **Associação a CVEs** conhecidas para versões específicas (Apache, PHP, OpenSSL etc).  

---

## ⚠️ Vulnerabilidades Detectadas e Riscos

### 1. **Portas Web Abertas**
- **Descrição**: portas abertas podem indicar serviços acessíveis (HTTP, HTTPS, painéis administrativos).  
- **Risco**: um atacante pode explorar portas expostas para encontrar aplicações vulneráveis, como um painel de administração sem proteção adequada.  
- **Exemplo**: se a porta `8080` estiver aberta e rodando **Tomcat**, o atacante pode explorar vulnerabilidades conhecidas nessa versão.

---

### 2. **Headers HTTP Inseguros**
- **Content-Security-Policy ausente** → pode permitir **XSS** (Cross-Site Scripting).  
- **X-Frame-Options ausente** → permite **Clickjacking** (atacar usuários com iframes invisíveis).  
- **Strict-Transport-Security ausente** → usuários podem ser forçados a usar HTTP (downgrade attack).  

**Exploração**:  
- Com falta de CSP, um atacante pode injetar `<script>alert(1)</script>` e roubar cookies de sessão.  
- Sem X-Frame-Options, é possível enganar usuários para clicarem em botões invisíveis (“likejacking”, “bank transfers”).  

---

### 3. **Paths Comuns Encontrados**
- **/admin**, **/phpmyadmin**, **/login**.  
- **Risco**: se acessíveis, podem permitir bruteforce ou exploração direta de vulnerabilidades no painel.  

**Exploração**:  
- `/phpmyadmin` exposto sem autenticação pode permitir controle total do banco de dados.  

---

### 4. **Tecnologias e CVEs**
- O scanner detecta frameworks/servidores com **Wappalyzer** e compara com uma lista de CVEs conhecidas.  
- Exemplos:  
  - **Apache/2.4.49** → vulnerável a **CVE-2021-41773** (Path Traversal + RCE).  
  - **OpenSSL/1.0.1** → vulnerável a **CVE-2014-0160 (Heartbleed)**, que permite roubo de memória do servidor.  
  - **PHP 5.x** → vulnerável a **CVE-2019-11043**, permitindo execução remota de código via PHP-FPM.  

---

## 📦 Instalação

Clone este repositório e instale os requisitos:

```bash
git clone https://github.com/Ramiyuu/redteamtools
pip install -r requirements.txt
