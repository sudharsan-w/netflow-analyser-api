from contextvars import ContextVar, Token


class ContextManager:

    def __init__(self, **vars):
        self._vars = {}
        self._name_to_vars = {}
        for k, v in vars.items():
            self.set_var(k, v)

    def _get_var(self, name):
        if name in self._vars:
            return self._vars[name]
        var = ContextVar(name)
        self._vars[name] = var
        return var

    def set_var(self, name, val):
        var = self._get_var(name)
        var.set(val)

    def get_val(self, var):
        if isinstance(var, ContextVar):
            return var.get()
        return self._get_var(var).get()


class AppContextManager(ContextManager):

    _default_app_context = {"app_name": None}

    def __init__(self, **vars):
        super().__init__(**{**self._default_app_context, **vars})

    @property
    def app(self):
        return self.get_val("app_name")


context = app_context = AppContextManager()
