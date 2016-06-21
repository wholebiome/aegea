class Loader:
    cache = dict(resource={}, client={})
    def __init__(self, factory):
        self.factory = factory

    def __getattr__(self, attr):
        if attr == '__all__':
            return list()
        elif attr == '__package__':
            return self.__package__
        elif attr == '__path__':
            return self.__path__
        elif attr == '__file__':
            return self.__file__
        elif attr == '__loader__':
            return None
        else:
            if attr not in self.cache[self.factory]:
                if self.factory == "client" and attr in self.cache["resource"]:
                    self.cache["client"][attr] = self.cache["resource"].meta.client
                else:
                    import boto3
                    factory = getattr(boto3, self.factory)
                    self.cache[self.factory][attr] = factory(attr)
            return self.cache[self.factory][attr]
