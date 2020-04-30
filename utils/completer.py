from prompt_toolkit.completion import Completer, Completion

class IMCompleter(Completer):

    def __init__(self, cls):
        self.cls = cls

    # Required by the Completer class
    # Document corresponds to the line hit by the user
    def get_completions(self, document, complete_event):
        word_before_cursor = document.get_word_before_cursor()

        # TODO: make something similar to autocomplete the
        # name of the options or modules
        
        for ctx in self.cls.prompt_session.contexts:
            if ctx.name.startswith(word_before_cursor) and ctx.name is not self.cls.name:
                yield Completion(ctx.name, -len(word_before_cursor))
        
        for cmd in self.cls._cmd_list:
            if cmd.startswith(word_before_cursor):
                yield Completion(cmd, -len(word_before_cursor))
        
        
