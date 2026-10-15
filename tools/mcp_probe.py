#!/home/jimmy/ctfenv/bin/python
"""MCP server enumeration/probing tool. Usage:
  mcp_probe.py stdio <command> [args...]      - connect over stdio to a local MCP server command
  mcp_probe.py sse <url>                      - connect over SSE/HTTP to a remote MCP server
Dumps every tool/resource/prompt's full raw description (where tool poisoning/hidden instructions
live), and offers to call a tool with chosen arguments for confused-deputy/injection testing.
Usage for a call: mcp_probe.py stdio <command> --call <tool_name> '<json args>'
"""
import sys, os, json, asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import find_flags
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def run(session: ClientSession, call_tool=None, call_args=None):
    await session.initialize()
    tools = await session.list_tools()
    print(f'== {len(tools.tools)} tool(s) ==')
    for t in tools.tools:
        print(f'- {t.name}')
        print(f'  description: {t.description!r}')
        schema = getattr(t, 'input_schema', None) or getattr(t, 'inputSchema', {})
        print(f'  inputSchema: {json.dumps(schema)}')
        fl = find_flags((t.description or '') + json.dumps(schema))
        if fl:
            print(f'  CANDIDATE (unverified) in tool metadata: {fl}')

    try:
        resources = await session.list_resources()
        print(f'\n== {len(resources.resources)} resource(s) ==')
        for r in resources.resources:
            print(f'- {r.uri}  {r.name!r}  {r.description!r}')
    except Exception as e:
        print(f'\n(no resources or not supported: {e})')

    try:
        prompts = await session.list_prompts()
        print(f'\n== {len(prompts.prompts)} prompt(s) ==')
        for p in prompts.prompts:
            print(f'- {p.name}  {p.description!r}')
    except Exception as e:
        print(f'\n(no prompts or not supported: {e})')

    if call_tool:
        print(f'\n== calling {call_tool} with {call_args} ==')
        result = await session.call_tool(call_tool, call_args or {})
        for c in result.content:
            text = getattr(c, 'text', str(c))
            print(text)
            fl = find_flags(text)
            if fl:
                print('CANDIDATE (unverified):', fl)


async def main():
    mode = sys.argv[1]
    call_tool, call_args = None, None
    args = sys.argv[2:]
    if '--call' in args:
        i = args.index('--call')
        call_tool = args[i + 1]
        call_args = json.loads(args[i + 2]) if len(args) > i + 2 else {}
        args = args[:i]

    if mode == 'stdio':
        params = StdioServerParameters(command=args[0], args=args[1:])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await run(session, call_tool, call_args)
    elif mode == 'sse':
        from mcp.client.sse import sse_client
        async with sse_client(args[0]) as (read, write):
            async with ClientSession(read, write) as session:
                await run(session, call_tool, call_args)
    else:
        print(__doc__)


asyncio.run(main())
