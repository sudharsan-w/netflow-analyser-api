async def iterate_async(iter):
    lis_ = []
    async for e in iter:
        lis_.append(e)
    return lis_
