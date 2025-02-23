from googleapiclient.discovery import build
from google.oauth2 import service_account
import re
from typing import List, Tuple

def get_table_from_google_doc(doc_id: str, credentials_path: str) -> List[List[List[str]]]:
    """
    Fetches and parses table content from a Google Doc.

    Args:
        doc_id (str): The ID of the Google Doc.
        credentials_path (str): Path to the service account JSON file.

    Returns:
        list: A list of tables, where each table is represented as a list of rows (rows are lists of cells).
    """
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path,
        scopes=['https://www.googleapis.com/auth/documents.readonly']
    )

    service = build('docs', 'v1', credentials=credentials)
    document = service.documents().get(documentId=doc_id).execute()

    tables = []
    for element in document.get('body', {}).get('content', []):
        if 'table' in element:
            table = element['table']
            parsed_table = []

            for row in table.get('tableRows', []):
                parsed_row = []
                for cell in row.get('tableCells', []):
                    cell_content = []
                    for content in cell.get('content', []):
                        text_elements = content.get('paragraph', {}).get('elements', [])
                        for text_element in text_elements:
                            if 'textRun' in text_element:
                                cell_content.append(text_element['textRun']['content'].strip())
                    parsed_row.append(" ".join(cell_content))
                parsed_table.append(parsed_row)

            tables.append(parsed_table)

    return tables

def get_table_data_without_header(table: List[List[str]]) -> List[List[str]]:
    """
    Retrieves table data, ignoring the first row (assumed to be a header).

    Args:
        table (list): A table represented as a list of rows (rows are lists of cells).

    Returns:
        list: The table data excluding the header row.
    """
    return table[1:] if len(table) > 1 else []

def interpret_table_data(table_data: List[List[str]]) -> List[Tuple[int, int, str]]:
    """
    Interprets table data as coordinates and symbols.

    Args:
        table_data (list): Table data excluding the header, where:
                          - Column 1: x-coordinate (column)
                          - Column 2: symbol
                          - Column 3: y-coordinate (row)

    Returns:
        list: A list of tuples (x, y, symbol) representing the interpreted data.
    """
    interpreted_data = []
    for row in table_data:
        if len(row) >= 3:
            try:
                x = int(row[0])
                y = int(row[2])
                symbol = row[1]
                interpreted_data.append((x, y, symbol))
            except ValueError:
                continue
    return interpreted_data

def display_interpreted_data(interpreted_data: List[Tuple[int, int, str]]) -> None:
    """
    Displays symbols on a screen-like grid based on x and y coordinates.

    Args:
        interpreted_data (list): A list of tuples (x, y, symbol).
    """
    max_x = max((x for x, _, _ in interpreted_data), default=0)
    max_y = max((y for _, y, _ in interpreted_data), default=0)

    grid = [[" " for _ in range(max_x + 1)] for _ in range(max_y + 1)]

    for x, y, symbol in interpreted_data:
        grid[max_y - y][x] = symbol

    for row in grid:
        print("".join(row))

def parse_doc_id_from_url(url: str) -> str:
    """
    Extracts the document ID from a Google Docs URL.

    Args:
        url (str): The URL of the Google Doc.

    Returns:
        str: The extracted document ID.
    """
    match = re.search(r'/d/([a-zA-Z0-9-_]+)', url)
    if match:
        return match.group(1)
    raise ValueError("Invalid Google Docs URL")

def render_google_doc(url: str) -> None:
    """
    Renders the content of a Google Doc by fetching and displaying tables.

    Args:
        url (str): The URL of the Google Doc.
    """
    CREDENTIALS_FILE = "/home/slysunkin/.config/gcloud/norse-glow-451805-m3-922b7f477f24.json"

    try:
        doc_id = parse_doc_id_from_url(url)
        tables = get_table_from_google_doc(doc_id, CREDENTIALS_FILE)
        for table in tables:
            table_data = get_table_data_without_header(table)
            interpreted_data = interpret_table_data(table_data)
            display_interpreted_data(interpreted_data)
            print()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    GOOGLE_DOC_URL = "https://docs.google.com/document/d/1Y7V7dNotEGDdslfUFIo5U4r7BWui59K6GcNJayeuM4g/edit?usp=sharing"
    render_google_doc(GOOGLE_DOC_URL)

'''
Sample output:

████████░     ████████░   ██████████░    ███████░  ██░           ███░ ███░    ███░ ██░     ██░
██░     ██░ ███░     ███░ ██░          ███░    ██░ ███░   ███░   ██░    ██░  ██░   ██░     ██░
██░     ██░ ██░       ██░ ██░         ███░          ██░  █████░ ███░     ██░██░    ██░     ██░
████████░   ██░       ██░ ████████░   ██░           ███░ ██░██░ ██░       ███░     ██████████░
██░     ██░ ██░       ██░ ██░         ███░           ██░██░ ██░██░       ██░██░    ██░     ██░
██░     ██░ ███░     ███░ ██░          ███░    ██░   ████░   ████░      ██░  ██░   ██░     ██░
████████░     ████████░   ██████████░    ███████░     ██░     ██░     ███░    ███░ ██░     ██░
'''
