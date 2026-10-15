"""Opt-in JSON diagnostics without email contents or navigation tokens."""
import json
import logging
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({'utc':datetime.now(timezone.utc).isoformat(), 'level':record.levelname, 'event':record.getMessage(), **getattr(record,'facts',{})}, ensure_ascii=False)


def configure():
    logger=logging.getLogger('antiphish')
    if not logger.handlers:
        handler=logging.StreamHandler(sys.stderr); handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO); logger.propagate=False


def completed(report):
    logging.getLogger('antiphish').info('analysis_complete',extra={'facts':{'sha256':report.input.get('sha256'), 'status':report.analysis_status.value, 'verdict':report.verdict.value, 'profile':report.configuration.get('profile'), 'network_status':report.configuration.get('network_analysis_status'), 'timings_ms':report.timings_ms, 'reasons':list(dict.fromkeys(e.code for e in report.reason_codes))}})
