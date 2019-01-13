#!/usr/bin/python3
import argparse
import collections
import difflib
import io
import logging
import multiprocessing
import os
import queue
import random
import re
import subprocess
import sys
import threading
import time

# import objgraph

# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s [%(levelname)s] [%(name)s]: %(message)s')
logging.basicConfig(level=logging.INFO,
                    format='[%(levelname)s] [%(name)s]: %(message)s')
logger = logging.getLogger(__name__)

INJECTED_SCRIPT = """'use strict';

rpc.exports.enumerateModules = function () {{
  return Process.enumerateModulesSync();
}};

var symbols = Module.enumerateSymbolsSync("{main_module_name}");
rpc.exports.enumerateSymbols = function () {{
  return symbols;
}}

var symbol_print_object,
    symbol_allocate_object,
    symbol_deallocate_object,
    symbol_tags_print,
    symbol_freelist_print,
    symbol_print_pointer,
    symbol_main,
    symbol_my_malloc,
    symbol_my_free;

for (var i = 0; i < symbols.length; i++) {{
  switch (symbols[i].name) {{
    case "print_object":
      symbol_print_object = symbols[i];
      break;
    case "allocate_object":
      symbol_allocate_object = symbols[i];
      break;
    case "deallocate_object":
      symbol_deallocate_object = symbols[i];
      break;
    case "my_malloc":
      symbol_my_malloc = symbols[i];
      break;
    case "my_free":
      symbol_my_free = symbols[i];
      break;
    case "tags_print":
      symbol_tags_print = symbols[i];
      break;
    case "freelist_print":
      symbol_freelist_print = symbols[i];
      break;
    case "print_pointer":
      symbol_print_pointer = symbols[i];
      break;
    case "main":
      symbol_main = symbols[i];
      break;
  }}
}}

var printf = new NativeFunction(
  Module.findExportByName("libc-2.27.so", "printf"),
  "void",
  ["pointer"]
);

var printfInt = new NativeFunction(
  Module.findExportByName("libc-2.27.so", "printf"),
  "void",
  ["pointer", "int"]
);

var tags_print = new NativeFunction(
  symbol_tags_print.address,
  "void",
  ["pointer"]
);

var freelist_print = new NativeFunction(
  symbol_freelist_print.address,
  "void",
  ["pointer"]
);

var print_pointer = new NativeFunction(
  symbol_print_pointer.address,
  "void",
  ["pointer"]
);

var startLog = Memory.allocUtf8String("LOG_START_1337\\n"); // LEEEEET!
var breakLog = Memory.allocUtf8String("TAGS\\n");
var endLog = Memory.allocUtf8String("LOG_END_1337\\n");
var mallocLog = Memory.allocUtf8String("LOG_MALLOC %d\\n");
var freeLog = Memory.allocUtf8String("LOG_FREE ");
var newlineLog = Memory.allocUtf8String("\\n");
var exitLog = Memory.allocUtf8String("LOG_EXIT\\n");

function logState() {{
  freelist_print(symbol_print_object.address);
  printf(breakLog);
  tags_print(symbol_print_object.address);
  printf(endLog);
}}

Interceptor.attach(symbol_my_malloc.address, {{
  onEnter: function (args) {{
    printf(startLog);
    send("MALLOC");
    printfInt(mallocLog, args[0].toInt32());

    // memory leak here
    // printf(Memory.allocUtf8String(args[0].toInt32().toString() + "\\n"));
  }},
  onLeave: function (ret) {{
    logState();
  }}
}});

Interceptor.attach(symbol_my_free.address, {{
  onEnter: function (args) {{
    printf(startLog);
    send("FREE");
    printf(freeLog);
    print_pointer(args[0]);
    printf(newlineLog);
  }},
  onLeave: function (ret) {{
    logState();
  }}
}});


Interceptor.attach(symbol_main.address, {{
  onEnter: function (ret) {{
   send("Entered main");
  }},
  onLeave: function (ret) {{
    printf(exitLog);
    send("Exited main");
  }}
}});

"""


def object_pool(class_):
    pools = {}

    if class_ not in pools:
        pools[class_] = {}

    def get_object(*args, **kwargs):
        new_object = class_(*args, **kwargs)

        if new_object not in pools[class_]:
            pools[class_][new_object] = new_object
            return new_object
        else:
            old_object = pools[class_][new_object]
            del new_object
            return old_object

    return get_object


AllocatorState = collections.namedtuple(
    'AllocatorState',
    ['prev_op', 'freelist_blocks', 'tags'])
AllocatorStateWrapper = AllocatorState

FreelistBlock = collections.namedtuple(
    'FreelistBlock',
    ['level', 'addr', 'size', 'left_size', 'allocated', 'prev', 'next'])
FreelistBlock.__new__.__defaults__ = (None,) * len(FreelistBlock._fields)
FreelistBlockWrapper = object_pool(FreelistBlock)

TagBlock = collections.namedtuple(
    'TagBlock',
    ['addr', 'size', 'left_size', 'allocated', 'prev', 'next'])
TagBlock.__new__.__defaults__ = (None,) * len(TagBlock._fields)
TagBlockWrapper = object_pool(TagBlock)


freelist_line_re = re.compile(r'L(\d+)')
freelist_block_possible_fields_re = list(map(
    lambda field: (field, re.compile('\t%s: ([\w\d]+)' % field)),
    ['addr', 'size', 'left_size', 'allocated', 'prev', 'next']
))


def parse_freelist(string):
    string = string.split("TAGS")[0]
    freelist = []

    # print(freelist_block_possible_fields_re)

    freelist_block_object = {}
    current_level = None
    # print(string)
    for line in string.split('\n'):
        match = freelist_line_re.match(line)
        if match:
            current_level = int(match.group(1))
        elif '[' in line:
            freelist_block_object = {}
        elif ']' in line:
            freelist.append(
                FreelistBlockWrapper(level=current_level,
                                     **freelist_block_object)  # BIG BRAIN PYTHON
            )
            freelist_block_object = {}
        else:
            for field, regex in freelist_block_possible_fields_re:
                match = regex.match(line)
                if match:
                    freelist_block_object[field] = match.group(1)
                    # print(line, regex.match(line).group(1))

    return freelist


tags_block_possible_fields_re = list(map(
    lambda field: (field, re.compile('\t%s: ([\w\d]+)' % field)),
    ['addr', 'size', 'left_size', 'allocated', 'prev', 'next']
))


def parse_tags(string):
    string = string.split("TAGS")[1]

    tags = []

    # print(tags_block_possible_fields_re)

    tags_block_object = {}
    # print(string)
    for line in string.split('\n'):
        if '[' in line:
            tags_block_object = {}
        elif ']' in line:
            tags.append(
                TagBlockWrapper(**tags_block_object)  # BIG BRAIN PYTHON
            )
            tags_block_object = {}
        else:
            for field, regex in tags_block_possible_fields_re:
                match = regex.match(line)
                if match:
                    tags_block_object[field] = match.group(1)
                    # print(line, regex.match(line).group(1))

    return tags


class BinAnalyser:
    def __init__(self, path, filename, queue):
        import frida
        from frida_tools.application import Reactor

        self._logger = logging.getLogger(self.__class__.__name__)

        self.path = path
        self.filename = filename
        self.states = queue

        self._stop_requested = threading.Event()
        self._reactor = Reactor(
            run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = frida.get_local_device()

        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(
            lambda: self._on_output(pid, fd, data)))  # pylint: disable=undefined-variable
        self.output = io.StringIO()

        self._mallocs = 0
        self._frees = 0
        self._output_counter = 0

    def exec(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()
        self.analyse()
        self.states.put('STOP')

    def _stop(self):
        self._stop_requested.set()

    def _start(self):
        self.pid = self._device.spawn(self.path, stdio='pipe')
        self._logger.info("Spawned new process. PID: %d", self.pid)

        session = self._device.attach(self.pid)
        session.on("detached", lambda reason: self._reactor.schedule(
            lambda: self._on_detached(self.pid, session, reason)))  # pylint: disable=undefined-variable
        self._logger.info("Session attached")
        session.enable_child_gating()

        script = session.create_script(
            INJECTED_SCRIPT.format(main_module_name=self.filename))
        script.on("message", lambda message, data: self._reactor.schedule(
            lambda: self._on_message(message, data)))  # pylint: disable=undefined-variable
        script.load()
        self._logger.info("Script loaded")
        self._print_progress(rewrite=False)

        self._device.resume(self.pid)

    # @profile
    def _on_output(self, pid, fd, data):
        if fd != 2 and pid == self.pid:
            self.output.write(data.decode())

            self._output_counter += 1
            if self._output_counter // 30 == 1:
                self._output_counter = 0
                self.analyse()

    def _on_detached(self, pid, session, reason):
        if pid == self.pid:
            self._logger.info("Session detached")
            self._reactor.schedule(self._stop, delay=0.5)

    def _on_message(self, message, data):
        if message['type'] == 'send':
            if message['payload'] == 'MALLOC':
                self._mallocs += 1
                self._print_progress()
            elif message['payload'] == 'FREE':
                self._frees += 1
                self._print_progress()
            else:
                self._logger.getChild('frida_script').info(message['payload'])
        else:
            self._logger.getChild('frida_script').error(message)

    def _print_progress(self, rewrite=True):
        # string = ''
        # if rewrite:
        #     string = '\r'

        # string += 'Mallocs: %d, Frees: %d' % (self._mallocs, self._frees)
        # sys.stdout.write(string)
        # sys.stdout.flush()
        pass

    # @profile
    def analyse(self):
        self.outputString = self.output.getvalue()
        self.output.close()
        self.output = io.StringIO()

        if not self.outputString:
            return

        for string in self.outputString.split('LOG_START_1337\n'):
            split = string.split('LOG_END_1337', maxsplit=1)
            if len(split) == 2:
                state_string_raw = split[0].strip()
                state_string_raw_split = state_string_raw.split(
                    '\n', maxsplit=1)
                if "LOG_MALLOC" in state_string_raw_split[0] or "LOG_FREE" in state_string_raw_split[0]:
                    self.states.put(
                        AllocatorStateWrapper(
                            prev_op=state_string_raw_split[0].replace(
                                'LOG_', ''),
                            freelist_blocks=parse_freelist(
                                state_string_raw_split[1]),
                            tags=parse_tags(state_string_raw_split[1])
                        ))
                else:
                    self.states.append(AllocatorState(
                        prev_op=None, state_string=state_string_raw))
            else:
                if "Segmentation fault" in string:
                    logger.error("Segmentation fault occurred")
                    sys.exit()

                self.output.write('LOG_START_1337\n')
                self.output.write(string)


def printColor(color):
    def _print(obj):
        print(color + str(obj) + '\033[0m')
    return _print


printRed = printColor('\033[31m')
printYellow = printColor('\033[33m')
printBlue = printColor('\033[34m')
printGreen = printColor('\033[32m')


def state_to_lines(state):
    return (
        [str(freelist_block) for freelist_block in state.freelist_blocks]
        + ['']
        + [str(tag) for tag in state.tags]
    )


def printDiff(test_state, target_state, prev_state):
    d = difflib.Differ()
    diff = d.compare(state_to_lines(target_state), state_to_lines(test_state))

    if prev_state:
        printBlue('\nPrevious State\n'
                  '--------------')
        print('\n'.join(state_to_lines(prev_state)))
    else:
        printRed('Previous State not available')

    printBlue('\nState Diff\n'
              '----------')

    printRed('RED - your output')
    printGreen('GREEN - test output')
    print()
    printBlue("After Operation: " + test_state.prev_op)

    for e in diff:
        if e.startswith("+"):
            printGreen(e)
        elif e.startswith("-"):
            printRed(e)
        elif e.startswith("?"):
            printYellow(e)
        else:
            print(e)


def compare(test_states, target_states):
    if len(test_states) != len(target_states):
        logger.warning("Incorrect number of states. Segfault?")

    for i in range(min(len(test_states), len(target_states))):
        test_state = test_states[i]
        target_state = target_states[i]
        # assert test_state.prev_op == target_state.prev_op

        if test_state != target_state:
            if i == 0:
                prev_state = None
            else:
                prev_state = target_states[i-1]
            printDiff(test_state, target_state, prev_state)

            return False

    return True


def worker(path, test_name, queue):
    logger.info("Processing %s", path)

    ba = BinAnalyser(path, test_name, queue)
    ba.exec()
    # objgraph.show_most_common_types()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('testcase', help='Testcase name. Ex.: test_all_lists')
    args = parser.parse_args()

    test_name = args.testcase

    logger.info("Testing %s", test_name)
    logger.info(
        "NOTE: This can take some time. Especially on large testcases (test_simple5, test_simple6)")

    test_path = "./tests/expected/" + test_name
    if not os.path.isfile(test_path):
        raise FileNotFoundError(test_path)

    target_path = "./tests/" + test_name
    if not os.path.isfile(target_path):
        raise FileNotFoundError(target_path)

    test_queue = multiprocessing.Queue()
    test_proc = multiprocessing.Process(
        target=worker, args=(test_path, test_name, test_queue))
    test_proc.start()

    target_queue = multiprocessing.Queue()
    target_proc = multiprocessing.Process(
        target=worker, args=(target_path, test_name, target_queue))
    target_proc.start()

    test_states = []
    target_states = []

    counter = 0

    try:
        while True:
            new_test_state = test_queue.get()  # blocking
            new_target_state = target_queue.get()  # blocking

            if new_test_state == 'STOP' and new_target_state == 'STOP':
                break

            if new_test_state == 'STOP' or new_target_state == 'STOP':
                logger.error("Incorrect number of states. Segfault?")
                test_proc.terminate()
                target_proc.terminate()
                sys.exit()
                # break

            test_states.append(new_test_state)
            target_states.append(new_target_state)

            if len(test_states) > 2:
                test_states.pop(0)

            if len(target_states) > 2:
                target_states.pop(0)

            if not compare(test_states, target_states):
                test_proc.terminate()
                target_proc.terminate()
                sys.exit()

            counter += 1
            if counter % 50 == 0:
                logger.info("Processed %d states", counter)

            # print(new_test_state)

        # objgraph.show_most_common_types()

        test_proc.join()
        target_proc.join()

        logger.info("Test passed")
    except KeyboardInterrupt:
        test_proc.terminate()
        target_proc.terminate()
