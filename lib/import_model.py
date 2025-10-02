import sys
import json
import asyncio

__all__ = ['get_config', 'import_server_model', 'export_model']

def get_config(config_json_path: str) -> dict|None:
    # Assuming you have a JSON file named 'data.json'
    config = None
    try:
        with open(config_json_path, 'r') as file:
            config = json.load(file)
    except FileNotFoundError:
        # Handle the case where the file does not exist
        print(f" The file '{config_json_path}' was not found.", file=sys.stderr)
    except json.JSONDecodeError as e:
        # Handle the case where the JSON data is invalid
        print(f" There was an error decoding the JSON data. {e}", file=sys.stderr)
    except Exception as e:
        # Handle any other exceptions
        print(f" There was some error with the JSON. {e}", file=sys.stderr)

    # 'data' is now a dictionary containing the JSON data
    print(config)
    return config

async def import_server_model(server, config_json_path) -> dict|None:

    server_model = {"nodes": [], "idx": {}}

    config = get_config(config_json_path)
    
    # if config == None or not "endpoint" in config:
        # print(f" No Server endpoint!", file=sys.stderr)
        # return None
    
    # Note: changed port from 4840 to 4841
    #       in order to not collide with default server, e.g. running from C-code
    # server.set_endpoint(config["endpoint"])
    
    for namespace in config["namespaces"] if "namespaces" in config else []:
        try:
            idx = await server.register_namespace(namespace)
        except Exception as e:
            # Handle any other exceptions
            print(f" register_namespace('{namespace}') error. {e}", file=sys.stderr)

        server_model["idx"][namespace] = idx
        print(f" Namespace '{namespace}' = {idx}")
    print("")

    for nodeset in config["nodeset2"] if "nodeset2" in config else []:
        print(f" Adding nodeset2 '{nodeset}'")
        try:
            server_model["nodes"] += await server.import_xml(nodeset)
        except Exception as e:
            # Handle any other exceptions
            print(f" import_xml('{nodeset}') error. {e}", file=sys.stderr)
        print("")

    return server_model

async def export_model(server, **kwargs):
    """
    kwargs:
        nodes: Optional list of nodes returned by `import_server_model` in its dictionary. If defined the export function will export the list of nodes, otherwise it will exports everithing in the server.
        xml_file_path: Optional string with the xml file name to store the exported model. Default is 'output.xml'.
    """

    print(" export_model.")

    nodes_list = []
    async def browse_recursive(node):
        children = await node.get_children()
        for child in children:
            nodes_list.append(child)
            await browse_recursive(child)

    xml_file_path = "output.xml"
    if "xml_file_path" in kwargs:
        xml_file_path = kwargs["xml_file_path"]
    
    if "nodes" in kwargs:
        nodes_list = [server.get_node(node) for node in kwargs["nodes"]]
    else:
        # Get the root node
        root = server.get_root_node()
        print(f" Root node: {root}")
        # Start browsing from the root node
        await browse_recursive(root)
    
    try:
        await server.export_xml(nodes_list, xml_file_path)
    except Exception as e:
        # Handle any other exceptions
        print(f" export_model error. {e}", file=sys.stderr)
