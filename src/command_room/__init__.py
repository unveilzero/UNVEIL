"""The command room: a separate, empty place where agent commands run.

The room is its own container. It holds no application data, no database and
no settings; it is given the chat workspaces and nothing else. The app sends a
command across (``client``), the room runs it inside a private namespace
(``server``) and sends the output back. Both halves use only the standard
library so the room needs nothing from the application to start.
"""
