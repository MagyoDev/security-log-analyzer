import csv
import json
from datetime import datetime
from pathlib import Path
from zipfile import ZipFile

import pandas as pd


EXPORTS_DIR = Path("exports")


def ensure_exports_dir():
    """
    Garante que a pasta exports existe.
    Se a pasta não existir, ela será criada automaticamente.
    """
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_timestamp():
    """
    Gera um timestamp para usar nos nomes dos arquivos.
    Exemplo:
    20260623-183000
    """
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def export_report_json(report: dict) -> Path:
    """
    Exporta o relatório completo em formato JSON.
    """
    ensure_exports_dir()

    output_path = EXPORTS_DIR / f"sla-report-{get_timestamp()}.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    return output_path


def export_report_markdown(report: dict) -> Path:
    """
    Exporta o relatório em Markdown.
    """
    ensure_exports_dir()

    output_path = EXPORTS_DIR / f"sla-report-{get_timestamp()}.md"

    lines = []

    lines.append("# S.L.A — Security Log Analyzer Report\n")
    lines.append(f"**Total packets captured:** {report['total_packets']}\n")
    lines.append(f"**Risk level:** {report['risk_level']}\n")

    direction = report["direction_summary"]

    lines.append("## Traffic Direction\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Local IP | {direction['local_ip']} |")
    lines.append(f"| Inbound | {direction['inbound']} |")
    lines.append(f"| Outbound | {direction['outbound']} |")
    lines.append(f"| Internal/Other | {direction['internal_or_other']} |")
    lines.append("")

    lines.append("## Protocols\n")
    lines.append("| Protocol | Packets | Percentage |")
    lines.append("|---|---:|---:|")

    for item in report["protocols"]:
        lines.append(
            f"| {item['protocol']} | {item['packets']} | {item['percentage']}% |"
        )

    lines.append("")

    lines.append("## Endpoints\n")
    lines.append("| IP | Hostname | Sent | Received | Total |")
    lines.append("|---|---|---:|---:|---:|")

    for item in report["endpoints"]:
        lines.append(
            f"| {item['ip']} | {item['hostname']} | {item['sent']} | "
            f"{item['received']} | {item['total']} |"
        )

    lines.append("")

    lines.append("## Flows\n")
    lines.append("| Endpoint A | Endpoint B | Packets |")
    lines.append("|---|---|---:|")

    for item in report["flows"]:
        lines.append(
            f"| {item['endpoint_a']} | {item['endpoint_b']} | {item['packets']} |"
        )

    lines.append("")

    lines.append("## Destination Ports\n")
    lines.append("| Port | Protocol | Service | Packets |")
    lines.append("|---:|---|---|---:|")

    for item in report["destination_ports"]:
        lines.append(
            f"| {item['port']} | {item['protocol']} | {item['service']} | "
            f"{item['packets']} |"
        )

    lines.append("")

    if report["dns_queries"]:
        lines.append("## DNS Queries\n")
        lines.append("| Domain | Count |")
        lines.append("|---|---:|")

        for domain, count in report["dns_queries"].items():
            lines.append(f"| {domain} | {count} |")

        lines.append("")

    if report["tcp_flags"]:
        lines.append("## TCP Flags\n")
        lines.append("| Flag | Count |")
        lines.append("|---|---:|")

        for flag, count in report["tcp_flags"].items():
            lines.append(f"| {flag} | {count} |")

        lines.append("")

    packet_lengths = report["packet_lengths"]

    lines.append("## Packet Lengths\n")
    lines.append(f"- **Min:** {packet_lengths['min']} bytes")
    lines.append(f"- **Max:** {packet_lengths['max']} bytes")
    lines.append(f"- **Average:** {packet_lengths['average']} bytes")
    lines.append("")

    lines.append("### Packet Length Buckets\n")
    lines.append("| Range | Packets |")
    lines.append("|---|---:|")

    for packet_range, count in packet_lengths["buckets"].items():
        lines.append(f"| {packet_range} | {count} |")

    lines.append("")

    lines.append("## Findings\n")

    for finding in report["findings"]:
        lines.append(f"- {finding}")

    with output_path.open("w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return output_path


def export_report_excel(report: dict) -> Path:
    """
    Exporta o relatório para Excel.
    """
    ensure_exports_dir()

    output_path = EXPORTS_DIR / f"sla-report-{get_timestamp()}.xlsx"

    protocols_df = pd.DataFrame(report["protocols"])
    endpoints_df = pd.DataFrame(report["endpoints"])
    flows_df = pd.DataFrame(report["flows"])
    ports_df = pd.DataFrame(report["destination_ports"])

    dns_df = pd.DataFrame(
        [
            {"domain": domain, "count": count}
            for domain, count in report["dns_queries"].items()
        ]
    )

    tcp_flags_df = pd.DataFrame(
        [
            {"flag": flag, "count": count}
            for flag, count in report["tcp_flags"].items()
        ]
    )

    findings_df = pd.DataFrame(
        [
            {"finding": finding}
            for finding in report["findings"]
        ]
    )

    direction_df = pd.DataFrame(
        [
            {
                "local_ip": report["direction_summary"]["local_ip"],
                "inbound": report["direction_summary"]["inbound"],
                "outbound": report["direction_summary"]["outbound"],
                "internal_or_other": report["direction_summary"]["internal_or_other"],
            }
        ]
    )

    packet_lengths_df = pd.DataFrame(
        [
            {
                "min": report["packet_lengths"]["min"],
                "max": report["packet_lengths"]["max"],
                "average": report["packet_lengths"]["average"],
            }
        ]
    )

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        direction_df.to_excel(writer, sheet_name="Direction", index=False)
        protocols_df.to_excel(writer, sheet_name="Protocols", index=False)
        endpoints_df.to_excel(writer, sheet_name="Endpoints", index=False)
        flows_df.to_excel(writer, sheet_name="Flows", index=False)
        ports_df.to_excel(writer, sheet_name="Ports", index=False)
        dns_df.to_excel(writer, sheet_name="DNS", index=False)
        tcp_flags_df.to_excel(writer, sheet_name="TCP Flags", index=False)
        packet_lengths_df.to_excel(writer, sheet_name="Packet Lengths", index=False)
        findings_df.to_excel(writer, sheet_name="Findings", index=False)

    return output_path


def write_csv(path: Path, fieldnames: list[str], rows: list[dict]):
    """
    Cria um arquivo CSV.
    """
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_report_csv_zip(report: dict) -> Path:
    """
    Exporta o relatório em vários CSVs e compacta tudo em um ZIP.
    """
    ensure_exports_dir()

    timestamp = get_timestamp()
    temp_dir = EXPORTS_DIR / f"sla-csv-{timestamp}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    zip_path = EXPORTS_DIR / f"sla-report-{timestamp}-csv.zip"

    write_csv(
        temp_dir / "protocols.csv",
        ["protocol", "packets", "percentage"],
        report["protocols"],
    )

    write_csv(
        temp_dir / "endpoints.csv",
        ["ip", "hostname", "sent", "received", "total"],
        report["endpoints"],
    )

    write_csv(
        temp_dir / "flows.csv",
        ["endpoint_a", "endpoint_b", "packets"],
        report["flows"],
    )

    write_csv(
        temp_dir / "ports.csv",
        ["port", "protocol", "service", "packets"],
        report["destination_ports"],
    )

    dns_rows = [
        {"domain": domain, "count": count}
        for domain, count in report["dns_queries"].items()
    ]

    write_csv(
        temp_dir / "dns.csv",
        ["domain", "count"],
        dns_rows,
    )

    tcp_flag_rows = [
        {"flag": flag, "count": count}
        for flag, count in report["tcp_flags"].items()
    ]

    write_csv(
        temp_dir / "tcp_flags.csv",
        ["flag", "count"],
        tcp_flag_rows,
    )

    findings_rows = [
        {"finding": finding}
        for finding in report["findings"]
    ]

    write_csv(
        temp_dir / "findings.csv",
        ["finding"],
        findings_rows,
    )

    with ZipFile(zip_path, "w") as zip_file:
        for csv_file in temp_dir.glob("*.csv"):
            zip_file.write(csv_file, arcname=csv_file.name)

    for csv_file in temp_dir.glob("*.csv"):
        csv_file.unlink()

    temp_dir.rmdir()

    return zip_path