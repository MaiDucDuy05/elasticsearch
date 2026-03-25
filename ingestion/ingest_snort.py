
import json, logging, sys
from pathlib import Path
from validator import validate_snort          
from bulk_indexer import get_client, bulk_index
from config import SNORT_INDEX              

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

def load_snort(filepath: str) -> list[dict]:  
    docs, skipped = [], 0
    with open(filepath, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning("Line %d: JSON parse error — %s", lineno, e)
                skipped += 1
                continue
            ok, reason = validate_snort(doc) 
            if not ok:
                logger.warning("Line %d: validation failed — %s", lineno, reason)
                skipped += 1
                continue
            docs.append(doc)
    logger.info("Loaded %d docs, skipped %d", len(docs), skipped)
    return docs

def run(filepath: str):
    client = get_client()
    docs   = load_snort(filepath)             
    if not docs:
        logger.error("No valid docs to index.")
        return
    success, errors = bulk_index(docs, SNORT_INDEX, client)  
    logger.info("Done — indexed: %d, errors: %d", success, len(errors))
    if errors:
        err_path = Path(filepath).stem + "_errors.json"
        with open(err_path, "w") as f:
            json.dump(errors, f, indent=2)
        logger.info("Error details saved to %s", err_path)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ingest_snort.py <snort_ndjson_file>")
        sys.exit(1)
    run(sys.argv[1])