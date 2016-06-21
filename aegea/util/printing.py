# coding: utf-8
from __future__ import absolute_import, division, print_function, unicode_literals

import os, sys, json, shutil, subprocess, re
from datetime import datetime

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

def CYAN(message=None):
    if message is None:
        return '\033[36m' if sys.stdout.isatty() else ''
    else:
        return CYAN() + message + ENDC()

def BLUE(message=None):
    if message is None:
        return '\033[34m' if sys.stdout.isatty() else ''
    else:
        return BLUE() + message + ENDC()

def YELLOW(message=None):
    if message is None:
        return '\033[33m' if sys.stdout.isatty() else ''
    else:
        return YELLOW() + message + ENDC()

def GREEN(message=None):
    if message is None:
        return '\033[32m' if sys.stdout.isatty() else ''
    else:
        return GREEN() + message + ENDC()

def RED(message=None):
    if message is None:
        return '\033[31m' if sys.stdout.isatty() else ''
    else:
        return RED() + message + ENDC()

def WHITE(message=None):
    if message is None:
        return '\033[37m' if sys.stdout.isatty() else ''
    else:
        return WHITE() + message + ENDC()

def UNDERLINE(message=None):
    if message is None:
        return '\033[4m' if sys.stdout.isatty() else ''
    else:
        return UNDERLINE() + message + ENDC()

def BOLD(message=None):
    if message is None:
        return '\033[1m' if sys.stdout.isatty() else ''
    else:
        return BOLD() + message + ENDC()

def ENDC():
    return '\033[0m' if sys.stdout.isatty() else ''

def strip_ansi_codes(i):
    return re.sub(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]", "", i)

def format_table(table, column_names=None, column_specs=None, max_col_width=32, report_dimensions=False):
    '''
    Table pretty printer. Expects tables to be given as arrays of arrays::

        print(format_table([[1, "2"], [3, "456"]], column_names=['A', 'B']))
    '''
    if len(table) > 0:
        col_widths = [0] * len(table[0])
    elif column_specs is not None:
        col_widths = [0] * (len(column_specs) + 1)
    elif column_names is not None:
        col_widths = [0] * len(column_names)
    my_col_names = []
    if column_specs is not None:
        column_names = ['Row']
        column_names.extend([col['name'] for col in column_specs])
        column_specs = [{'name': 'Row', 'type': 'float'}] + column_specs
    if column_names is not None:
        for i in range(len(column_names)):
            my_col = str(column_names[i])
            if len(my_col) > max_col_width:
                my_col = my_col[:max_col_width-1] + '…'
            my_col_names.append(my_col)
            col_widths[i] = max(col_widths[i], len(strip_ansi_codes(my_col)))
    my_table = []
    for row in table:
        my_row = []
        for i in range(len(row)):
            my_item = str(row[i])
            if len(my_item) > max_col_width:
                my_item = my_item[:max_col_width-1] + '…'
            my_row.append(my_item)
            col_widths[i] = max(col_widths[i], len(strip_ansi_codes(my_item)))
        my_table.append(my_row)

    def border(i):
        return WHITE() + i + ENDC()

    type_colormap = {'boolean': BLUE(),
                     'integer': YELLOW(),
                     'float': WHITE(),
                     'string': GREEN()}
    for i in 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64':
        type_colormap[i] = type_colormap['integer']
    type_colormap['double'] = type_colormap['float']

    def col_head(i):
        if column_specs is not None:
            return BOLD() + type_colormap[column_specs[i]['type']] + column_names[i] + ENDC()
        else:
            return BOLD() + WHITE() + column_names[i] + ENDC()

    formatted_table = [border('┌') + border('┬').join(border('─')*i for i in col_widths) + border('┐')]
    if len(my_col_names) > 0:
        padded_column_names = [col_head(i) + ' '*(col_widths[i]-len(my_col_names[i])) for i in range(len(my_col_names))]
        formatted_table.append(border('│') + border('│').join(padded_column_names) + border('│'))
        formatted_table.append(border('├') + border('┼').join(border('─')*i for i in col_widths) + border('┤'))

    for row in my_table:
        padded_row = [row[i] + ' '*(col_widths[i]-len(strip_ansi_codes(row[i]))) for i in range(len(row))]
        formatted_table.append(border('│') + border('│').join(padded_row) + border('│'))
    formatted_table.append(border('└') + border('┴').join(border('─')*i for i in col_widths) + border('┘'))

    if report_dimensions:
        return '\n'.join(formatted_table), len(formatted_table), sum(col_widths) + len(col_widths) + 1
    else:
        return '\n'.join(formatted_table)

def page_output(content, pager=None, file=None):
    if file is None:
        file = sys.stdout
    if not content.endswith("\n"):
        content += "\n"

    pager_process = None
    try:
        if file != sys.stdout or not file.isatty():
            raise Exception()
        content_lines = content.splitlines()
        content_rows = len(content_lines)

        tty_rows, tty_cols = shutil.get_terminal_size()

        naive_content_cols = max(len(i) for i in content_lines)
        if tty_rows > content_rows and tty_cols > naive_content_cols:
            raise Exception()

        content_cols = max(len(strip_ansi_codes(i)) for i in content_lines)
        if tty_rows > content_rows and tty_cols > content_cols:
            raise Exception()
        # FIXME
        raise Exception()
        pager_process = subprocess.Popen(pager or os.environ.get('PAGER', 'less -RS'), shell=True,
                                         stdin=subprocess.PIPE, stdout=file)
        pager_process.stdin.write(content.encode("utf-8"))
        pager_process.stdin.close()
        pager_process.wait()
        if pager_process.returncode != os.EX_OK:
            raise Exception()
    except Exception:
        file.write(content.encode("utf-8") if USING_PYTHON2 else content)
    finally:
        try:
            pager_process.terminate()
        except:
            pass

def get_field(item, field):
    for element in field.split("."):
        try:
            item = getattr(item, element)
        except AttributeError:
            try:
                item = item.get(element)
            except AttributeError:
                raise Exception('Unable to access field or attribute "{}" of {}'.format(field, item))
    return item

def format_datetime(d):
    d = d.replace(microsecond=0)
    if not USING_PYTHON2:
        # Switch from UTC to local TZ
        d = d.astimezone(tz=None)
    return str(d)

def get_cell(resource, field, transform=None):
    cell = get_field(resource, field)
    cell = transform(cell) if transform else cell
    if isinstance(cell, datetime):
        cell = format_datetime(cell)
    return ", ".join(i.name for i in cell.all()) if hasattr(cell, "all") else cell

def format_tags(cell):
    tags = {tag["Key"]: tag["Value"] for tag in cell} if cell else {}
    return ", ".join("{}={}".format(k, v) for k, v in tags.items())

def trim_names(names, *prefixes):
    for name in names:
        for prefix in prefixes:
            if name.startswith(prefix):
                name = name[len(prefix):]
        yield name

def tabulate(collection, args, cell_transforms=None):
    if cell_transforms is None:
        cell_transforms = {}
    cell_transforms["tags"] = format_tags
    if getattr(args, "json", None):
        table = [{f: get_cell(i, f, cell_transforms.get(f)) for f in args.columns} for i in collection]
        return json.dumps(table, indent=2)
    else:
        table = [[get_cell(i, f, cell_transforms.get(f)) for f in args.columns] for i in collection]
        if getattr(args, "sort_by", None):
            reverse = False
            if args.sort_by.endswith(":reverse"):
                reverse = True
                args.sort_by = args.sort_by[:-len(":reverse")]
            table = sorted(table, key=lambda x: x[args.columns.index(args.sort_by)], reverse=reverse)
        args.columns = list(trim_names(args.columns, *getattr(args, "trim_col_names", [])))
        return format_table(table,
                            column_names=getattr(args, "display_column_names", args.columns),
                            max_col_width=args.max_col_width)

class Timestamp:
    def __init__(self, ts):
        ts = int(ts)
        self.timestamp = datetime.fromtimestamp(ts//1000)

    def __str__(self):
        return str(self.timestamp)
