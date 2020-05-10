# Usage description for docopt
"""
IoTMap

Usage: 
    iotmap.py [ database [--import_pcap <pcapfile> <protocol> | --clear_database | --export_db <path> | --import_db <path>]
              | sniffing [--channel <channel>] [--timeout <timeout>] [--packetnb <packetnb>] [--protocol <protocol>] [--nbthread <nbthread>] [--output <filename>]
              | exploit 
              | modelling [--level <level>] ]

Options: 
    -h, --help                           Show this help menu.
    -v, --version                        Show version.

    database                             Use database mode.
    --clear_database                     Clear the current database
    -i, --import_pcap <file> <protocol>  Pcap file to import in the database.
    -e, --export_db <path>               Export the database to PATH.
    -d, --import_db <path>               Load a database dump (this action removes the current database).

    sniffing                             Use live sniffing mode.
    -c, --channel <channel>              Channel to sniff [default: 15].
    -t, --timeout <timeout>              Numbers of second to sniff [default: 15].
    -p, --packetnb <packetnb>            Numbers of packets to sniff [default: 100].
    --protocol <protocol>                Protocol to use at the layer 3 [default: zigbee]
    -m, --nbthread nbthread              Number of threads allocated to process the analysis of the communications intercepted [default: 4].
    -o, --output filename                Output file to store the result of the sniffing [default: unified_format.csv].

    exploit                              Use exploit mode.

    modelling                            Use modelling mode.
    -l level, --level level              Set the number of layers of the graph [default: 4].
"""


from core.databaseController import DBController
import subprocess
import functools
from shlex import split
from docopt import docopt, DocoptExit
from prompt_toolkit import PromptSession
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter, PathCompleter
from core.sniffing import Sniffing
from core.database import Database
from core.modelling import Modelling
from utils.utils import main_help, wait_until_DB_is_UP


class IoTMap:
    def __init__(self):
        self.name="main"
        self.prompt_session = PromptSession(
            'IoTMap > ',
            auto_suggest=AutoSuggestFromHistory(),
            enable_history_search=True,
            complete_in_thread=True,
            complete_while_typing=True
        )

        self.dc = DBController()
        self.options = self.get_options()
        
        self.contexts = [
            Sniffing(self.prompt_session, self.dc, self.options['sniffing']),
            Database(self.prompt_session, self.dc),
            Modelling(self.prompt_session, self.dc, self.options['modelling']),
        ]

        self.prompt_session.completer = WordCompleter([ctx.name for ctx in self.contexts] + ['exit', 'help'], ignore_case=True)
        self.prompt_session.contexts = self.contexts
        self.prompt_session.path_completer = PathCompleter()
        self.current_context = self

    # This function returns the options given
    # by the user
    def get_options(self):  
        module_name = [m for m in ['sniffing', 'database', 'modelling', 'exploit'] if args[f'{m}']]
        
        sniffing = {
            'command': 'run',
            'channel': args['--channel'],
            'timeout': args['--timeout'],
            'packetNb': args['--packetnb'],
            'protocol': args['--protocol'],
            'output': args['--output'],
            'nbthread': args['--nbthread'],
        }

        modelling = {
            'command': '',
            'level': args['--level'],
        }
        
        options = {
            'module': module_name,
            'sniffing': sniffing,
            'modelling': modelling,
        }
        
        if args['database']:
            table_opt_db = ['clear_database', 'import_pcap', 'export_db', 'import_db']
            cmd_db = [opt for opt in table_opt_db if not(not args[f'--{opt}'])]
            args_db = ''
            
            if cmd_db:
                cmd_db = str(cmd_db[0])
                if args[f'--{cmd_db}'] is not True: args_db = args[f'--{cmd_db}']
                if cmd_db == 'import_pcap': args_db += f' {args["<protocol>"]}' 
            else :
                cmd_db = ''
                
            database = {
                'command': f'{cmd_db} {args_db}'
            }
            
            options['database'] = database

        # if args['modelling']:
        #     options['modelling'] = {
        #         'command': '',
        #         'level': args['--level']
        #     }
            
        if args['exploit']:
            options['exploit'] = {
                'command': 'exploit'
            }
            
        return options

    # Run command set with the command line and stay on the
    # good context
    def run_options(self):
        module = self.options['module'][0]
        self.context_switching(module)

        command = self.options[f'{module}']['command'].strip()
        if len(command) > 0:
            res = self.prompt_session.prompt(accept_default=True, default=command)
            self.parse_result(res)

    def context_switching(self, func):
        for context in self.contexts:
            if context.name == func:
                self.prompt_session.message = context.prompt
                self.prompt_session.completer = context.completer
                self.current_context = context
                return True
        return False

    def parse_result(self, result):
        if len(result):
            if not self.context_switching(result):
                command = split(result)
                try:
                    bound_cmd_handler = functools.partial(getattr(self.current_context, command[0]), args=command[1:])
                    run_in_terminal(bound_cmd_handler)
                except TypeError:
                    print (f"Error type")
                except AttributeError as ae:
                    print (f"Error with the command '{command[0]}':\n{ae}")
                except DocoptExit as e:
                    print(str(e))
                except SystemExit:
                    pass

    def __call__(self):
        if self.options['module']:
            self.run_options()
            
        while True:
            result = self.prompt_session.prompt()
            if result == 'help' and self.current_context.name == 'main':
                print(main_help())
                continue
            
            if result == 'exit':
                break

            self.parse_result(result)


if __name__ == '__main__':  
    version=0.1
    
    banner = f"""\
                                                                                                                   
                                                                                                                   
IIIIIIIIII              TTTTTTTTTTTTTTTTTTTTTTTMMMMMMMM               MMMMMMMM                                     
I::::::::I              T:::::::::::::::::::::TM:::::::M             M:::::::M                                     
I::::::::I              T:::::::::::::::::::::TM::::::::M           M::::::::M                                     
II::::::II              T:::::TT:::::::TT:::::TM:::::::::M         M:::::::::M                                     
  I::::I     oooooooooooTTTTTT  T:::::T  TTTTTTM::::::::::M       M::::::::::M  aaaaaaaaaaaaa  ppppp   ppppppppp   
  I::::I   oo:::::::::::oo      T:::::T        M:::::::::::M     M:::::::::::M  a::::::::::::a p::::ppp:::::::::p  
  I::::I  o:::::::::::::::o     T:::::T        M:::::::M::::M   M::::M:::::::M  aaaaaaaaa:::::ap:::::::::::::::::p 
  I::::I  o:::::ooooo:::::o     T:::::T        M::::::M M::::M M::::M M::::::M           a::::app::::::ppppp::::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M  M::::M::::M  M::::::M    aaaaaaa:::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M   M:::::::M   M::::::M  aa::::::::::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M    M:::::M    M::::::M a::::aaaa::::::a p:::::p     p:::::p
  I::::I  o::::o     o::::o     T:::::T        M::::::M     MMMMM     M::::::Ma::::a    a:::::a p:::::p    p::::::p
II::::::IIo:::::ooooo:::::o   TT:::::::TT      M::::::M               M::::::Ma::::a    a:::::a p:::::ppppp:::::::p
I::::::::Io:::::::::::::::o   T:::::::::T      M::::::M               M::::::Ma:::::aaaa::::::a p::::::::::::::::p 
I::::::::I oo:::::::::::oo    T:::::::::T      M::::::M               M::::::M a::::::::::aa:::ap::::::::::::::pp  
IIIIIIIIII   ooooooooooo      TTTTTTTTTTT      MMMMMMMM               MMMMMMMM  aaaaaaaaaa  aaaap::::::pppppppp    
                                                                                                p:::::p            
                                                                                                p:::::p            
                                                                                               p:::::::p           
                                                                                               p:::::::p           
                                                                                               p:::::::p           
                                                                                               ppppppppp           
                                                                                                                   

                                Version={version}
"""		
    args = docopt(__doc__, version=version)
    
    command = "./database/neo4j-community/bin/neo4j start"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    
    print(banner)
    wait_until_DB_is_UP()

    # print('Database is available at http://localhost:7474/ \n')
    iotmap = IoTMap()
    iotmap()
    
    command = "./database/neo4j-community/bin/neo4j stop"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
