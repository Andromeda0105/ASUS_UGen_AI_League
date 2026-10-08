"""Bounded local imports. Diagnostics deliberately exclude untrusted log text."""
import os
import re

from app.parsers.ssh import parse_ssh_line
from app.parsers.nginx import parse_nginx_line


def limits():
    return {
        'max_files': int(os.getenv('UPLOAD_MAX_FILES', '8')),
        'max_file_bytes': int(os.getenv('UPLOAD_MAX_FILE_BYTES', str(2 * 1024 * 1024))),
        'max_total_bytes': int(os.getenv('UPLOAD_MAX_TOTAL_BYTES', str(8 * 1024 * 1024))),
        'max_lines_per_file': int(os.getenv('UPLOAD_MAX_LINES', '10000')),
        'max_line_bytes': int(os.getenv('UPLOAD_MAX_LINE_BYTES', '16384')),
    }


def safe_filename(name):
    return re.sub(r'[\x00-\x1f\x7f]', '', (name or 'unnamed.log').replace('\\', '/').rsplit('/', 1)[-1])[:200] or 'unnamed.log'


def parse_import(data, filename, source_type, *, ssh_year=None):
    """One result for every file, one accepted/rejected decision for every line."""
    report = dict(filename=safe_filename(filename), source_type=source_type, byte_count=len(data),
                  line_count=0, accepted_lines=0, rejected_lines=0, unique_event_count=0,
                  duplicate_lines=0, status='rejected', issues=[], issues_omitted=0,
                  ssh_year=ssh_year if source_type == 'ssh' else None,
                  timezone=os.getenv('LOG_TIMEZONE', 'Asia/Taipei') if source_type == 'ssh' else 'log_offset')
    if not data:
        report['issues'] = [{'line': None, 'reason': '檔案為空或只有空白。'}]
        return [], report
    try:
        text = data.decode('utf-8-sig')
    except UnicodeDecodeError:
        report['line_count'] = len(data.splitlines())
        report['rejected_lines'] = report['line_count']
        report['issues'] = [{'line': None, 'reason': '檔案必須使用 UTF-8 編碼。'}]
        return [], report
    lines = text.splitlines()
    report['line_count'] = len(lines)
    if len(lines) > limits()['max_lines_per_file']:
        raise ValueError('檔案超過行數上限。')
    if not text.strip():
        report['rejected_lines'] = len(lines)
        report['issues'] = [{'line': None, 'reason': '檔案只有空白，沒有可解析事件。'}]
        return [], report
    events = []
    seen = set()
    for number, line in enumerate(lines, 1):
        reason = None
        event = None
        if len(line.encode('utf-8')) > limits()['max_line_bytes']:
            reason = '單行超過長度上限。'
        elif not line.strip():
            reason = '空白行。'
        else:
            try:
                event = parse_ssh_line(line, year=ssh_year) if source_type == 'ssh' else parse_nginx_line(line)
            except (ValueError, OverflowError):
                reason = '日期、時區或欄位無效。'
            if event is None and reason is None:
                reason = ('SSH 非支援的認證事件或格式／日期無效；目前只解析 Failed password 與 Accepted 登入。'
                          if source_type == 'ssh' else '不符合 Nginx combined access log 格式或日期無效。')
        if event is None:
            report['rejected_lines'] += 1
            if len(report['issues']) < 100:
                report['issues'].append({'line': number, 'reason': reason})
            else:
                report['issues_omitted'] += 1
        else:
            report['accepted_lines'] += 1
            if event.id in seen:
                report['duplicate_lines'] += 1
            else:
                seen.add(event.id)
                events.append(event)
    report['unique_event_count'] = len(events)
    report['status'] = 'partial' if events and report['rejected_lines'] else 'accepted' if events else 'rejected'
    return events, report
