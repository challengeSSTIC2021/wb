#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
import json
from jsonschema import validate
import os
import secrets
import struct

GUEST_PERM = 0xffffffffffffffff

schema_input = {
  "type": "array",
  "items": {
    "oneOf": [
      {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "outdir": {
            "type": "string"
          },
          "type": {
            "type": "string"
          },
          "prod": {
            "type": "boolean"
          },
          "guest": {
            "type": "null"
          }
        },
        "required": [
          "name",
          "outdir",
          "type",
          "guest"
        ]
      },
      {
        "type": "object",
        "properties": {
          "name": {
            "type": "string"
          },
          "outdir": {
            "type": "string"
          },
          "type": {
            "type": "string"
          },
          "prod": {
            "type": "boolean"
          },
          "perms": {
            "type": "integer",
            "minimum": 0
          }
        },
        "required": [
          "name",
          "outdir",
          "type",
          "perms"
        ]
      }
    ]
  }
}

schema_key = {
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "key": {
        "type": "string"
      },
      "perms": {
        "type": "integer",
        "minimum": 0
      },
      "ident": {
        "type": "integer",
        "minimum": 0
      }
    },
    "required": [
      "key",
      "perms",
      "ident"
    ]
  }
}

schema_index = {
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "name": {
        "type": "string"
      },
      "real_name": {
        "type": "string"
      },
      "type": {
        "type": "string"
      },
      "perms": {
        "type": "string"
      },
      "ident": {
        "type": "string"
      }
    },
    "required": [
      "name",
      "real_name",
      "type",
      "perms",
      "ident"
    ]
  }
}

def convert_json(p, pretty=False):
    if pretty:
        return json.dumps(p, sort_keys=True, indent=4)
    else:
        return json.dumps(p)

def cipher_and_write(content, output_dir):
    key = secrets.token_bytes(16)
    obj = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
    c_content = obj.encrypt(content)

    content_sha = sha256(c_content).digest().hex()
    output_name = content_sha + ".enc"

    with open(os.path.join(output_dir, output_name), 'wb') as f:
        f.write(c_content)

    return output_name, key

def decode_file(name, ident, keys, output_dir):
    key = bytes.fromhex(keys[ident]['key'])
    assert len(key) == 16

    with open(os.path.join(output_dir, name), 'rb') as f:
        content = f.read()

    assert sha256(content).digest().hex() + ".enc" == name

    obj = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=1))
    plain = obj.decrypt(content)
    return plain

def gen_ident(keys, need_prod=False):
    while True:
        ident = struct.unpack('>Q', secrets.token_bytes(8))[0]
        if need_prod:
            ident |= (1<<63)
        else:
            ident &= ((1<<63) - 1)
        if ident not in keys:
            return ident

class Dir:

    def __init__(self):
        self.max_perm = 0
        self.prod_only = True
        self.subdir = {}
        self.file = []
        self.names = []

    def append(self, info, path, need_prod):
        path = os.path.normpath(path)
        pathl = []
        while '/' in path:
            path, t = os.path.split(path)
            pathl = [t] + pathl
        if path not in ["", "."]:
            pathl = [path] + pathl
        self._append(info, pathl, need_prod)

    def _append(self, info, path, need_prod):

        self.max_perm = max(self.max_perm, struct.unpack('>Q', bytes.fromhex(info["perms"]))[0])
        self.prod_only &= need_prod

        if path == []:
            assert info["real_name"] not in self.names
            self.names.append(info["real_name"])
            self.file.append(info)
            return

        d = path[0]
        assert d not in ["", ".", ".."]


        if d not in self.subdir:
            assert d not in self.names
            self.names.append(d)
            self.subdir[d] = Dir()

        self.subdir[d]._append(info, path[1:], need_prod)

    def gen_index(self, keys, output_dir):

        for dname, d in self.subdir.items():
            content = d.gen_index(keys, output_dir)

            name, key = cipher_and_write(content.encode('utf8'), output_dir)

            ident = gen_ident(keys, d.prod_only)

            keys[ident] = {
                "key": key.hex(),
                "perms": d.max_perm
            }
            self.file.append( {
                "name": name,
                "real_name": dname,
                "type": "dir_index",
                "perms": struct.pack('>Q', d.max_perm).hex(),
                "ident": struct.pack('>Q', ident).hex()
            })
        self.file.sort(key=lambda x: x['real_name'])
        index = convert_json(self.file)
        return index


def run(conf, input_dir, output_dir):
    keys = {}
    out_file = {}
    root = Dir()
    for e in conf:
        with open(os.path.join(input_dir, e["name"]), 'rb') as f:
            content = f.read()

        name, key = cipher_and_write(content, output_dir)

        if "guest" in e:
            perm = GUEST_PERM
        else:
            perm = e['perms']

        need_prod = e.get('prod', False)

        ident = gen_ident(keys, need_prod)

        keys[ident] = {
            "key": key.hex(),
            "perms": perm
        }

        root.append( {
            "name": name,
            "real_name": os.path.basename(e["name"]),
            "type": e["type"],
            "perms": struct.pack('>Q', perm).hex(),
            "ident": struct.pack('>Q', ident).hex()
        }, os.path.normpath(e["outdir"]), need_prod)

    root_index = root.gen_index(keys, output_dir)

    with open(os.path.join(output_dir, "index.json"), "w") as f:
        f.write(root_index)

    return keys


def check_file(entry, directory, plain, input_data, input_dir, prod_only):
    found = None

    for i in range(len(input_dir)):
        # same directory and real name
        if ( entry['real_name'] == os.path.basename(input_data[i]['name']) and
                os.path.normpath(directory) == os.path.normpath(input_data[i]['outdir'])):
            found = i
            break

    assert found != None
    config_entry = input_data[i]

    # good permission
    if 'guest' in config_entry:
        assert int(entry['perms'], 16) == GUEST_PERM
    else:
        assert int(entry['perms'], 16) == config_entry['perms']

    # check prod_only
    assert prod_only == config_entry.get('prod', False)

    # same content
    with open(os.path.join(input_dir, config_entry["name"]), 'rb') as f:
        assert f.read() == plain

    del input_data[i]

def check(input_data, input_dir, keys, output_dir, index, current_dir=".", current_perms=GUEST_PERM, prod_only=False):

    for entry in index:
        ident = int(entry['ident'], 16)
        eperm = int(entry['perms'], 16)

        plain = decode_file(entry['name'], ident, keys, output_dir)

        # the permission files should match the one in key-server
        assert keys[ident]["perms"] == eperm

        # the permission cannot be less permissive than the one for the current directory
        assert current_perms >= eperm
        perm = min(current_perms, eperm)

        # if the directory is prod_only, all file must be prod_only
        assert (not prod_only) or (ident & (1<<63))

        if entry["type"] == "dir_index":
            nested_index = json.loads(plain.decode('utf8'))
            validate(instance=nested_index, schema=schema_index)
            nested_dir = os.path.join(current_dir, entry['real_name'])
            check(input_data, input_dir, keys, output_dir, nested_index, nested_dir, perm, (ident & (1<<63)))
        else:
            check_file(entry, current_dir, plain, input_data, input_dir, (ident & (1<<63)) != 0)

    if current_dir == ".":
        # all input_file has been check
        assert input_data == []

if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--check", action='store_true', help="Check the output")
    parser.add_argument("--no-run", action='store_true', help="Do not run")
    parser.add_argument("--clean", action='store_true', help="clean all files of the output directory before add the new files")

    parser.add_argument("-i", "--input-dir", type=str, help="input file directory", default="files")
    parser.add_argument("-I", "--input-json", type=str, help="json input files", default="files.json")
    parser.add_argument("-o", "--output-dir", type=str, help="output file directory", default="output")
    parser.add_argument("-k", "--output-key", type=str, help="output key files", default="keys.json")

    args = parser.parse_args()

    if args.no_run and not args.check:
        parser.error('Nothing to do, remove --no-run or add --check')

    if args.no_run and args.clean:
        parser.error('--clean must be used with --check')

    if not os.path.isfile(args.input_json):
        parser.error('Cannot found {}'.format(args.input_json))

    with open(args.input_json, 'r') as f:
        input_data = json.loads(f.read())

    validate(instance=input_data, schema=schema_input)

    if not os.path.isdir(args.input_dir):
        parser.error('Cannot found {}'.format(args.input_dir))

    if os.path.exists(args.output_key) and not os.path.isfile(args.output_key):
        parser.error('{} exists and is not a file'.format(args.output_key))

    if not args.no_run:

        if not os.path.isdir(args.output_dir):
            print("Create {}".format(args.output_dir))
            os.makedirs(args.output_dir, mode=0o755, exist_ok=True)

        if args.clean:
            for filename in os.listdir(args.output_dir):
                file_path = os.path.join(args.output_dir, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)

        keys = run(input_data, args.input_dir, args.output_dir)
        keys = [{"ident": i, **d} for i, d in keys.items()]
        with open(args.output_key, 'w') as f:
            f.write(convert_json(keys, pretty=True))

    if args.check:

        if not os.path.isdir(args.output_dir):
            parser.error('Cannot found {}'.format(args.output_dir))

        with open(args.output_key, 'r') as f:
            jkeys = json.loads(f.read())
        validate(instance=jkeys, schema=schema_key)

        keys = {}
        for j in jkeys:
            keys[j['ident']] = j

        with open(os.path.join(args.output_dir, "index.json"), 'r') as f:
            root_index = json.loads(f.read())
        validate(instance=root_index, schema=schema_index)

        check(input_data[:], args.input_dir, keys, args.output_dir, root_index)


