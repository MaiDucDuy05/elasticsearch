# bulk_indexer.py
import logging
from elasticsearch import Elasticsearch, helpers
from config import ES_HOST, ES_USER, ES_PASSWORD, BATCH_SIZE, MAX_RETRIES

logger = logging.getLogger(__name__)

def get_client() -> Elasticsearch:
    client_args = {
        "hosts": [ES_HOST],
        "max_retries": MAX_RETRIES,
        "retry_on_timeout": True,
    }
    
    # Chỉ dùng xác thực nếu có user
    if ES_USER and ES_PASSWORD:
        client_args["basic_auth"] = (ES_USER, ES_PASSWORD)
    
    # Bật/tắt SSL tùy thuộc vào host là http hay https
    if ES_HOST.startswith("https"):
        client_args["verify_certs"] = False  # Đổi thành folder certs thật khi production
    else:
        client_args["verify_certs"] = False

    return Elasticsearch(**client_args)

def _make_actions(docs: list[dict], index: str):
    """Generator — yield từng action cho Bulk API."""
    for doc in docs:
        yield {
            "_index": index,
            "_source": doc,
        }

def bulk_index(docs: list[dict], index: str, client: Elasticsearch):
    """
    Gửi docs lên ES. Trả về (success_count, error_list).
    streaming_bulk tự chia batch theo chunk_size.
    """
    success, errors = 0, []

    for ok, result in helpers.streaming_bulk(
        client,
        _make_actions(docs, index),
        chunk_size=BATCH_SIZE,
        raise_on_error=False,        # không throw — ta xử lý lỗi thủ công
        raise_on_exception=False,
    ):
        if ok:
            success += 1
        else:
            action, info = result.popitem()
            errors.append(info)
            logger.warning("Index error: %s", info)

    return success, errors