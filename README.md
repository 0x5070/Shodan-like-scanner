Network Discovery and Enumeration Suite

Un conjunto de herramientas avanzadas en Bash diseñadas para la exploración masiva y auditoría de redes mediante la generación aleatoria de objetivos IPv4 y escaneo de alta velocidad.
Herramienta Principal: all-in-one-find.sh (v6.0)

La evolución definitiva de la suite. A diferencia de los motores basados solo en Nmap, este script utiliza Masscan para el descubrimiento global a velocidades de hasta 5000 pps (paquetes por segundo).
Caracteristicas Tecnicas:

    Filtro de Honeypots: Omite automaticamente IPs que exponen el puerto 666 (Doom/Pentbox) para evitar sistemas trampa.

    Escaneo Multihilo Asincrono: Utiliza Masscan para el radar inicial y lanza procesos Nmap en segundo plano para la auditoria profunda. 

    Persistencia de Sesion: Soporte nativo para pausar y reanudar el escaneo (paused.conf) sin perder el progreso.

    Protocolos Auditados: FTP (Anonymous), SSH (Banners), Telnet (No-Auth), SMB (Guest), RDP (OS Info) y VNC (No-Auth).

Otras Herramientas incluidas:

    ipfind.sh: Motor de descubrimiento general mediante pings y escaneos agresivos con Nmap.

    webfind2.sh: Escaner multihilo especializado en activos web (HTTP/S) y verificacion de estados (200 OK).

    printerfind.sh: Auditoria IoT enfocada en protocolos de impresion (JetDirect, IPP, LPD).

    telnetfind2.sh: Escaner de protocolos legacy para detectar servicios Telnet abiertos.

English Version: Shodan-style IP Scanner

This suite is a high-performance collection of Bash-based tools for global network reconnaissance. The flagship script, all-in-one-find.sh, leverages Masscan for internet-wide scanning and Nmap for deep service inspection.
Technical Specifications (v6.0):

    Honeypot Mitigation: Automatically ignores hosts with port 666 open to filter out deception systems.

    High-Speed Discovery: Capable of scanning at 5000+ pps, covering the IPv4 space efficiently.

    Session Management: Built-in resume support using paused.conf.

    Deep Inspection: Specialized checks for unauthenticated FTP, SMB, VNC, and Telnet access.

Disclaimer / Aviso Legal

Este proyecto ha sido desarrollado exclusivamente con fines educativos y de seguridad etica. El autor no se hace responsable del mal uso de estas herramientas. Realizar escaneos sobre redes de terceros sin autorizacion puede ser ilegal.

This project was developed for educational and ethical security purposes only. Unauthorized network scanning may be illegal in your jurisdiction. Use responsibly.

Uso / Usage

# Otorgar permisos de ejecucion
chmod +x *.sh

# El escaneo masivo requiere privilegios de root para paquetes RAW (Masscan/Nmap)
sudo ./all-in-one-find.sh
