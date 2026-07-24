"""Password manager export formats."""

import csv
import io
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime

__all__ = ["export_json", "export_csv", "export_keepass", "PasswordEntry"]


@dataclass
class PasswordEntry:
    """A single password entry for export.

    Attributes:
        title: Entry title (e.g., "GitHub").
        username: Username or email.
        password: The password.
        url: Website URL (optional).
        notes: Additional notes (optional).
        group: Group or folder (optional).
    """

    title: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    group: str = ""


def export_json(entries: list[PasswordEntry], indent: int = 2) -> str:
    """Export password entries as JSON.

    Args:
        entries: List of PasswordEntry objects to export.
        indent: JSON indentation level (default 2).

    Returns:
        JSON string.

    Examples:
        >>> entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        >>> print(export_json(entries))
        [
          {
            "title": "GitHub",
            "username": "user@email.com",
            ...
          }
        ]
    """
    data = []
    for entry in entries:
        data.append(
            {
                "title": entry.title,
                "username": entry.username,
                "password": entry.password,
                "url": entry.url,
                "notes": entry.notes,
                "group": entry.group,
            }
        )
    return json.dumps(data, indent=indent)


def export_csv(entries: list[PasswordEntry]) -> str:
    """Export password entries as CSV.

    Args:
        entries: List of PasswordEntry objects to export.

    Returns:
        CSV string.

    Examples:
        >>> entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        >>> print(export_csv(entries))
        title,username,password,url,notes,group
        GitHub,user@email.com,s3cure!,,,
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["title", "username", "password", "url", "notes", "group"])
    for entry in entries:
        writer.writerow(
            [
                entry.title,
                entry.username,
                entry.password,
                entry.url,
                entry.notes,
                entry.group,
            ]
        )
    return output.getvalue()


def export_keepass(entries: list[PasswordEntry]) -> str:
    """Export password entries as KeePass XML.

    Args:
        entries: List of PasswordEntry objects to export.

    Returns:
        KeePass XML string.

    Examples:
        >>> entries = [PasswordEntry("GitHub", "user@email.com", "s3cure!")]
        >>> print(export_keepass(entries))
        <?xml version="1.0" encoding="UTF-8"?>
        <KeePassFile>
          <Group>
            <Entry>
              <Title>GitHub</Title>
              ...
            </Entry>
          </Group>
        </KeePassFile>
    """
    root = ET.Element("KeePassFile")
    group_elem = ET.SubElement(root, "Group")
    group_elem.append(ET.Element("Name"))
    group_elem[-1].text = "Passwords"

    for entry in entries:
        entry_elem = ET.SubElement(group_elem, "Entry")

        title_elem = ET.SubElement(entry_elem, "Title")
        title_elem.text = entry.title

        username_elem = ET.SubElement(entry_elem, "UserName")
        username_elem.text = entry.username

        password_elem = ET.SubElement(entry_elem, "Password")
        password_elem.text = entry.password

        if entry.url:
            url_elem = ET.SubElement(entry_elem, "URL")
            url_elem.text = entry.url

        if entry.notes:
            notes_elem = ET.SubElement(entry_elem, "Notes")
            notes_elem.text = entry.notes

        times_elem = ET.SubElement(entry_elem, "Times")
        created_elem = ET.SubElement(times_elem, "CreationTime")
        created_elem.text = datetime.now().isoformat()

    ET.indent(root, space="  ")
    xml_str = ET.tostring(root, encoding="unicode", xml_declaration=True)
    return xml_str
