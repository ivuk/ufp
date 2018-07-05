class BaseFormatter():
    """
    Base representation of a formatter
    """
    def __init__(self, entries, options):
        self.entries = entries
        self.options = options
        self.hostname_cache = {}

    def get_action_repr(self, parsed_line):
        if self.options.colorize:
            allow = '\u2705'
            block = '\u274C'
        else:
            allow = 'ALLOW'
            block = 'BLOCK'

        if parsed_line.allowed():
            action = allow
        else:
            action = block

        return action

    def format(self):
        raise NotImplemented
