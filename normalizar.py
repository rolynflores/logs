#!/usr/bin/env python3
"""
normalizar.py — Normaliza las 6 fuentes de telemetría del Caso Akira a un esquema común
y construye la línea de tiempo del incidente.

Esquema común de salida (linea_tiempo.csv):
    timestamp_utc, fuente, tipo_evento, ip_origen, ip_destino, usuario, descripcion

Reglas de normalización de hora:
  - camara_ip_syslog.log           -> ya en UTC, pero SIN año (syslog clásico): se asume 2025.
  - firewall_perimetral.csv        -> epoch Unix, ya en UTC.
  - netflow_interno.csv            -> epoch Unix, ya en UTC.
  - edr_alert.json                 -> ISO 8601 con 'Z', ya en UTC.
  - server_files01_eventos_seguridad.csv -> hora LOCAL de Lima (UTC-5): sumar 5 horas.
  - anydesk_session.log            -> hora LOCAL de Lima (UTC-5), sin zona horaria: sumar 5 horas.
"""
import csv
import json
import re
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
LIMA_OFFSET = timedelta(hours=5)  # sumar para pasar de hora Lima a UTC
ANIO_ASUMIDO = 2025

rows = []  # cada fila: (datetime_utc, fuente, tipo_evento, ip_origen, ip_destino, usuario, descripcion)


def parse_syslog(path):
    meses = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}
    pat = re.compile(r"<\d+>(\w{3}) (\d+) (\d+):(\d+):(\d+) (\S+) (\w+): (.+)")
    with open(path) as f:
        for line in f:
            m = pat.match(line.strip())
            if not m:
                continue
            mon, day, h, mi, s, host, proc, msg = m.groups()
            ts = datetime(ANIO_ASUMIDO, meses[mon], int(day), int(h), int(mi), int(s), tzinfo=UTC)
            ip = ""
            im = re.search(r"from ([\d.]+)", msg)
            if im:
                ip = im.group(1)
            tipo = "login_fallido" if "failure" in msg else ("login_exitoso" if "success" in msg else "evento_sistema")
            rows.append((ts, "camara_ip_syslog.log", tipo, ip, host, "admin" if "admin" in msg else "", msg))


def parse_firewall(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            ts = datetime.fromtimestamp(int(r["timestamp_epoch"]), tz=UTC)
            desc = f"{r['accion']} regla={r['regla']} puerto={r['puerto_destino']}/{r['protocolo']} bytes={r['bytes_salientes']}"
            rows.append((ts, "firewall_perimetral.csv", "trafico_perimetral", r["ip_origen"], r["ip_destino"], "", desc))


def parse_windows_security(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            # "14/10/2025 10:14:47 a. m." -> dd/mm/yyyy hh:mm:ss + am/pm (locale es-PE)
            txt = r["TimeCreated"].replace("a. m.", "AM").replace("p. m.", "PM")
            dt_local = datetime.strptime(txt, "%d/%m/%Y %I:%M:%S %p")
            ts = (dt_local + LIMA_OFFSET).replace(tzinfo=UTC)
            evid = r["EventID"]
            tipo = {"4624": "logon_exitoso", "4625": "logon_fallido", "4688": "proceso_creado"}.get(evid, "evento_windows")
            desc = f"EventID {evid} LogonType={r['LogonType']} Workstation={r['WorkstationName']}"
            rows.append((ts, "server_files01_eventos_seguridad.csv", tipo, r["SourceNetworkAddress"], "server-files-01", r["AccountName"], desc))


def parse_netflow(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        for r in reader:
            ts = datetime.fromtimestamp(int(r["timestamp_epoch"]), tz=UTC)
            desc = f"escaneo puerto {r['puerto_destino']}/{r['protocolo']} resultado={r['resultado']}"
            rows.append((ts, "netflow_interno.csv", "escaneo_interno", r["ip_origen"], r["ip_destino"], "", desc))


def parse_anydesk(path):
    """TODO (estudiantes): completar este parser.

    Formato de cada línea del archivo anydesk_session.log:
        'YYYY-MM-DD HH:MM:SS.mmm ( I) <mensaje>'
    Ejemplo real:
        2025-10-14 10:40:22.118 ( I) Session started, Session-ID: 44213309

    La hora es LOCAL de Lima (UTC-5), SIN zona horaria indicada en el archivo
    -- hay que sumarle 5 horas (LIMA_OFFSET) para obtener la hora UTC, igual
    que ya se hizo en parse_windows_security() más arriba.

    Completen este parser para que, por cada línea del archivo, agreguen una
    fila a `rows` con la misma tupla de 7 campos que usan las demás funciones:
        (ts, "anydesk_session.log", tipo_evento, ip_origen, ip_destino, usuario, descripcion)

    Pista de tipo_evento: usen "conexion_remota" para las líneas de sesión/conexión,
    y "ejecucion_remota" para la línea de "Remote command execution".
    Pista de IP: la IP remota (198.51.100.77) es la misma en todas las líneas de este archivo.
    """
    # Reemplacen este bloque por su propia implementación.
    raise NotImplementedError("parse_anydesk() todavía no está implementado — ver Parte 4.2 de la Guía de Actividad.")


def parse_edr(path):
    with open(path) as f:
        data = json.load(f)
    ts = datetime.strptime(data["timestamp_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    desc = f"{data['detection_name']} accion={data['action_taken']} sha256={data['file_sha256'][:16]}... parent={data['process_parent']}"
    rows.append((ts, "edr_alert.json", "deteccion_malware", "", data["hostname"], "", desc))


def main():
    parse_syslog("camara_ip_syslog.log")
    parse_firewall("firewall_perimetral.csv")
    parse_windows_security("server_files01_eventos_seguridad.csv")
    parse_netflow("netflow_interno.csv")
    parse_anydesk("anydesk_session.log")
    parse_edr("edr_alert.json")

    rows.sort(key=lambda r: r[0])

    with open("linea_tiempo.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["timestamp_utc", "fuente", "tipo_evento", "ip_origen", "ip_destino", "usuario", "descripcion"])
        for ts, fuente, tipo, ip_o, ip_d, user, desc in rows:
            w.writerow([ts.strftime("%Y-%m-%dT%H:%M:%SZ"), fuente, tipo, ip_o, ip_d, user, desc])

    print(f"{len(rows)} eventos normalizados -> linea_tiempo.csv")


if __name__ == "__main__":
    main()
