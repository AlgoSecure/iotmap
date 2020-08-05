from functools import wraps
from docopt import docopt, DocoptExit
from terminaltables import AsciiTable
import re
import time
import requests

# The list of available protocols
list_protocol = ['os4i', 'zigbee', 'btle'] 

class CmdError(Exception):
    pass

# Command decorator
def command(func):
    func._command = True
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Retrieve arguments
        try :
            # print(f"[i] {kwargs['args']}")
            cmd_args = docopt(func.__doc__.strip(), argv=kwargs["args"])
            # print(f"[i] {cmd_args}")
        except:
            # print(f"[d] Something's wrong with arguments\n\n{docopt(func.__doc__.strip(), argv=kwargs['args'])}") 
            return wrapper
        
        correct_args = {}
        # Func.__annotations__ allows to get arguments
        # required by the function func
        for name, hint in func.__annotations__.items():
            #print(f"[d] - {name} : {hint}")
            try:
                value = cmd_args[f'<{name}>']
            except KeyError:
                try:
                    value = cmd_args[f'--{name}']
                except:
                    raise CmdError(f"Unable to find '{name}' argument in command definition")

            if value is not None:
                correct_args[name] = hint(value)
            
        return func(args[0], **correct_args)

    return wrapper

# Get all commands
def cls_commands(cls):
    cls._cmd_list = []
    for commandName in dir(cls):
        command = getattr(cls, commandName)
        if hasattr(command, '_command'):
            cls._cmd_list.append(commandName)

    return cls


def check_protocol(protocol):
    """
    This is a temporary function which checks if the protocol 
    given by the user is available!
    """
    is_ok = True
    for p in protocol:
        if not p.lower() in list_protocol:
            is_ok = False
            break
        
    return is_ok


# Restructure the list of pcaps
def unify_pcaps(protocols, pcaps):
    pcaps_list = {}

    for i in range(0, len(protocols)):
        if protocols[i] not in pcaps_list.keys():
            pcaps_list[protocols[i]] = []

        pcaps_list[protocols[i]].append(pcaps[i])
        
    return pcaps_list

def main_help():

    commands = ['database', 'sniffing', 'exploit', 'modelling', 'exit']
    description = ['Use database mode.', 'Use sniffing mode.', 'Use exploit mode.', 'Use modelling mode.', 'Quit this program']

    table_data = [['Commands', 'Description']]
    
    for i in range(len(commands) - 1):
        table_data.append([commands[i], description[i]])
            
        table = AsciiTable(table_data)
        table.inner_column_border = False
        table.inner_footing_row_border = False
        table.inner_heading_row_border = True
        table.inner_row_border = False
        table.outer_border = False
        
        msg = f"""
Core commands
=============

{table.table}\n\n"""
    return msg


# This function converts strings that represent an array to the corresponding array
# and returns the results.
# Expecting return: A list of array that describes the graph
def convert_str_to_array(tab):
    retTab = []
    for line in tab:
        line = line.replace('\'', '').replace('\"', '')
        tmp = re.findall("\[([^\[\]]+)\]", line)
        array = []
        for t in tmp:
            if ',' in t:
                t = t.split(', ')
            else:
                t = [t]
            array.append(t)
        # array.append(line.split(', ')[-1])
        retTab.append(array)
    return retTab



# This function compares two arrays and returns two values
# the result of A - B and the result of B - A
# In other words, the function returns the missing and extra elements of B compare to A
def compare2arrays(arrayA, arrayB):

    falseNeg = []
    falsePos = []
    truePos = []

    # This loop returns missing elements in arrayB according
    # to the arrayA
    for lineA in arrayA:
        isIn = False
        # print(f"lineA : {lineA} : {len(lineA)}")
        for lineB in arrayB:
            # print(f"lineB: {lineB} : {len(lineB)}")
            count = 0
            for i in range(len(lineA)):
                if set(lineB[i]) == set(lineA[i]):
                    count+=1

            if count == len(lineA):
                isIn = True
                break
            
        if not isIn:
            falseNeg.append(lineA)

    # This loop returns extra elements in arrayB according
    # to the arrayA
    for lineB in arrayB:
        notIn = True
        for lineA in arrayA:
            count = 0
            for i in range(len(lineA)):
                if set(lineB[i]) == set(lineA[i]):
                    count+=1

            if count == len(lineB):
                notIn = False

        if notIn:
           falsePos.append(lineB)
        else:
            truePos.append(lineB)

    return falseNeg, falsePos, truePos


def readNodesFile(filename):
    nodes = []
    try:
        with open(filename, 'r') as csvFile:
            for line in csvFile.readlines():
                tmpLine = line.strip().split(', ')
                tmpLine[0] = int(tmpLine[0])
                for i in range(1, len(tmpLine)):
                    tmpLine[i] = tmpLine[i].split(';')

                nodes.append(tmpLine)

    except IOError as ioe:
        #print(f"CSVFile: {csvData}")
        print(f'Error while opening the file...\n{ioe}')
        return False
    except e:
        #print(f"CSVFile: {csvData}")
        print(f'Error while opening into CSV file...{e}')
        return False

    return nodes

def wait_until_DB_is_UP():
    status_code = 404
    eof = ['/', '—', '\\', '|']
    i = 0
    while status_code != 200:
        try:
            req = requests.get("http://127.0.0.1:7474")
            status_code = req.status_code
        except:
            time.sleep(1)
            print('Starting the database ' + eof[i%4], end='\r')
            i+=1
            continue
    print("Database is available at http://localhost:7474/ \n")