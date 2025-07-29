# IoT History CLI
This command-line interface (CLI) tool is designed to retrieve historical tag data from the **Network Asset** and **Client Edge** API's. It takes in a site id or tag id as arguments and exports a flattened CSV of the data.

---
## Prerequisites
Before you begin, ensure you have the following installed on your system:
- **[Python](https://www.python.org/downloads/)** (this script was tested with Python version 3.12, so 3.12+ is recommended)
- **[Poetry](https://python-poetry.org/docs/)** (a tool for dependency management and packaging in Python)

---
## Installation & Setup
Follow these steps to get the project running on your local machine.

### 1. Clone the Repository
First, clone this repository to your local machine.

```bash
git clone https://github.com/LinkLabs/iot-history-cli
cd iot-history-cli
```

### 2. Install Dependencies
Second, install the script's dependencies using poetry.

```bash
poetry install
```

### 3. Verify Project Setup
To verify that the project setup was successful, run the following command in the project's root directory.
```bash
poetry run python src/get_tag_history.py --help
```

If the project setup was successful, this message will appear in the terminal.
```
usage: get_tag_history.py [-h] (--site_id SITE_ID | --tag_id TAG_ID) [--output FILENAME] [--username USERNAME] [--flush_pages NUMBER_PAGES] [--max_retries MAX_RETRIES] [--before END_DATE | --continue]
                          [--after START_DATE | --days_back NUMBER_DAYS]

Extract historical data for a site or tag and save it as a flattened CSV file.

options:
  -h, --help            show this help message and exit
  --site_id SITE_ID     ID of the site to query (mutually exclusive with --tag_id)
  --tag_id TAG_ID       ID of the tag to query (mutually exclusive with --site_id)
  --output FILENAME, -o FILENAME
                        Custom output CSV filename
  --username USERNAME   Link Labs Conductor username for authentication
  --flush_pages NUMBER_PAGES
                        Number of pages to buffer before writing to CSV (default: 20). Use 0 to write only once at the end.
  --max_retries MAX_RETRIES
                        Maximum retry attempts for failed API requests (default: 3).
  --before END_DATE     UTC ISO8601 end timestamp (default: now UTC)
  --continue            Resume: use the latest timestamp from the output CSV as the --before time (mutually exclusive with --before)
  --after START_DATE    UTC ISO8601 start timestamp. Mutually exclusive with --days_back.
  --days_back NUMBER_DAYS
                        Number of days before --before to use as the start timestamp (mutually exclusive with --after)
```

---
## Usage
All commands should be run from the project's root directory.

### Command Examples

**Example 1: Get the past week's data history from a specific site**

```bash
poetry run python src/get_tag_history.py --site_id SITE_ID
```

**Example 2: Get January's data history from a specific tag**

```bash
poetry run python src/get_tag_history.py --tag_id TAG_ID --after 2025-01-01T00:00:00Z --before 2025-02-01T00:00:00Z
```

**Example 3: Get the past sixty day's data history from a specific tag and output to a custom file**

```bash
poetry run python src/get_tag_history.py --tag_id TAG_ID --days_back 60 --output FILENAME
```

---
## Argument Reference

The script uses specific commands to target different APIs and arguments to filter the queries.

### Arguments

|Argument|Description|Format|Required?|
|---|---|---|---|
|`-h`, `--help`|`Show this help message and exit`|N/A|No|
|`--site_id SITE_ID`|`ID of the site to query (mutually exclusive with --tag_id)`|1111aaaa-22bb-33cc-44dd-555555eeeeee|Yes|
|`--tag_id TAG_ID`|`ID of the tag to query (mutually exclusive with --site_id)`|$501$0-0-0000a1b-2c3d4e5f6|Yes|
|`-o`, `--output FILENAME`|`Custom output CSV filename`|filename.csv|No|
|`--username USERNAME`|`Link Labs Conductor username for authentication`|email address|No|
|`--flush_pages NUMBER_PAGES`|`Number of pages to buffer before writing to CSV (default: 20). Use 0 to write only once at the end.`|integer|No|
|`--max_retries MAX_RETRIES`|`Maximum retry attempts for failed API requests (default: 3).`|integer|No|
|`--before END_DATE`|`UTC ISO8601 end timestamp (default: now UTC)`|UTC ISO8601 date string|No|
|`--continue`|`Resume: use the latest timestamp from the output CSV as the --before time (mutually exclusive with --before)`|N/A|No|
|`--after START_DATE`|`UTC ISO8601 start timestamp.`|UTC ISO8601 date string|No|
|`--days_back NUMBER_DAYS`|`Number of days before the END_DATE to use as the start timestamp (mutually exclusive with --after)`|integer|No|

---
## Troubleshooting
Here's a list of common issues and their solutions.

### Poetry setup errors
**Error message:** `poetry command not found`
- **Solution:** this could be caused by a number of different issue, but it is most likely due to poetry not being installed or not being added to your system's PATH.

### Script argument errors
**Error message:** `get_tag_history.py: error: argument --tag_id: expected one argument`
- **Solution:** make sure to escape the tag id's dollar sign in your terminal.

**Error message:** `get_tag_history.py: error: argument --site_id: not allowed with argument --tag_id`
- **Solution:** `--tag_id` and `--site_id` are mutually exclusive.