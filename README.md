# Always - HackMyVM Lösungsweg

![Always VM Icon](Always.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Always".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Always
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Einfach (Easy)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Always](https://hackmyvm.eu/machines/machine.php?vm=Always)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Always_HackMyVM_Easy/](https://alientec1908.github.io/Always_HackMyVM_Easy/)
*   **Datum des Originalberichts:** 13. Februar 2025

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `rdesktop`
*   `ftp`
*   `enum4linux`
*   `crackmapexec` / `nxc` / `netexec`
*   `msfvenom`
*   `msfconsole` (Metasploit)
*   `python3 http.server`
*   `base64`

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Potenzielle Benutzernamen notiert: `ftpuser`, `always`, `administrator`.
*   Die Ziel-IP `192.168.2.176` wurde mittels `arp-scan -l` identifiziert.
*   Der Hostname `always.hmv` wurde der IP `192.168.2.176` in der `/etc/hosts`-Datei des Angreifers zugeordnet.
*   Ein `nmap` UDP-Scan fand Port `137/udp` (NetBIOS Name Service) offen.
*   Ein `nmap` TCP-Scan identifizierte offene Ports, typisch für ein Windows-System:
    *   **Port 21/tcp (FTP):** Microsoft ftpd.
    *   **Port 135/tcp (MSRPC), 139/tcp (NetBIOS-SSN), 445/tcp (SMB):** Standard Windows-Dienste (Windows 7 Professional SP1). SMB-Signing war deaktiviert.
    *   **Port 3389/tcp (RDP):** `tcpwrapped`.
    *   **Port 5357/tcp (HTTP):** Microsoft HTTPAPI (Service Unavailable).
    *   **Port 8080/tcp (HTTP):** Apache httpd 2.4.57 (Win64), zeigte eine "We Are Sorry"-Seite. TRACE-Methode aktiviert.
    *   Diverse dynamische RPC-Ports.

### 2. Web Enumeration (Port 8080)

*   `nikto` auf `http://always.hmv:8080/` fand:
    *   Fehlende Security-Header (`X-Frame-Options`, `X-Content-Type-Options`).
    *   Aktive TRACE-Methode.
    *   Potenzielles Admin-Verzeichnis `/admin/` und `admin/index.html`.
*   `gobuster` bestätigte das `/admin/`-Verzeichnis.
*   RDP-Verbindungsversuche mit `rdesktop` scheiterten.
*   Anonymes FTP-Login scheiterte.
*   `enum4linux` bestätigte Workgroup-Namen und Computerdetails.
*   `smbclient -L \\\\192.168.2.176` (anonym) schlug fehl, Shares aufzulisten.
*   **Kritischer Fund:** Im Quellcode von `http://always.hmv:8080/admin/` wurden **hardcodierte JavaScript-Anmeldedaten** gefunden: `admin` / `adminpass123`.

### 3. Initial Access (Credentials & FTP)

1.  **Zugriff auf Admin-Bereich:**
    *   Login auf `http://always.hmv:8080/admin/` mit `admin:adminpass123`.
    *   Auf der Seite `admin_notes.html` wurde ein Base64-kodierter String gefunden: `ZnRwdXNlcjpLZWVwR29pbmdCcm8hISE=`.
    *   Dekodierung ergab FTP-Credentials: **`ftpuser:KeepGoingBro!!!`**.
2.  **FTP-Zugriff:**
    *   Erfolgreicher Login am FTP-Server (Port 21) mit `ftpuser:KeepGoingBro!!!`.
    *   `robots.txt` wurde heruntergeladen und enthielt `Disallow: /admins-secret-pagexxx.html`.
3.  **Weitere Credentials gefunden:**
    *   Aufruf von `http://always.hmv:8080/admins-secret-pagexxx.html` enthüllte eine Notiz mit einem weiteren Base64-String: `WW91Q2FudEZpbmRNZS4hLiE=`.
    *   Dekodierung ergab Credentials für den Benutzer `always`: **`always:YouCantFindMe.!.!`**.
4.  **Credential-Tests:**
    *   SSH (Port 22) war geschlossen.
    *   `nxc` (NetExec) bestätigte die Gültigkeit von `ftpuser:KeepGoingBro!!!` für FTP und SMB. Die Credentials für `always` funktionierten für diese Dienste nicht.
    *   RDP-Login als `ftpuser` scheiterte weiterhin.

### 4. Reverse Shell Setup & Manuelle Ausführung

*   Eine Windows x64 Meterpreter Reverse HTTPS Payload (`shell.exe`) wurde mit `msfvenom` generiert (LHOST: Angreifer-IP, LPORT: 443).
*   Ein Python HTTP-Server wurde auf dem Angreifer-System gestartet, um `shell.exe` bereitzustellen.
*   **Manueller Eingriff:** Der Tester loggte sich direkt in die VM ein (Tastaturlayout angepasst), lud `shell.exe` über den Browser herunter und führte sie aus.
    *(Dieser Schritt stellt eine Abweichung vom rein externen Angriffspfad dar.)*
*   Ein `msfconsole`-Handler (`exploit/multi/handler`) wurde (nach anfänglichen Konfigurationsfehlern) korrekt mit LHOST (Angreifer-IP) und LPORT 443 gestartet.
*   Eine Meterpreter-Session als Benutzer **`Always-PC\ftpuser`** wurde geöffnet.

### 5. Privilege Escalation (AlwaysInstallElevated)

1.  **Schwachstellen-Identifizierung:**
    *   In der Meterpreter-Session wurde das Metasploit-Modul `multi/recon/local_exploit_suggester` ausgeführt.
    *   Das Modul identifizierte die Windows-Konfiguration **`AlwaysInstallElevated`** als verwundbar.
2.  **Ausnutzung mit Metasploit:**
    *   Das Modul `exploit/windows/local/always_install_elevated` wurde verwendet.
    *   Die aktive `ftpuser`-Meterpreter-Session wurde als Ziel gesetzt.
    *   Nach Ausführung des Exploits wurde eine neue Meterpreter-Session mit **`NT AUTHORITY\SYSTEM`**-Rechten geöffnet.
3.  **Flags auslesen:**
    *   Über die SYSTEM-Shell wurden die Flags gefunden und ausgelesen.

### 6. Flags

*   **User-Flag (`C:\Users\Always\Desktop\user.txt`):**
    ```
    HMV{You_Found_Me!}
    ```
*   **Root-Flag (`C:\Users\Administrator\Desktop\root.txt`):**
    ```
    HMV{White_Flag_Raised}
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Always" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
