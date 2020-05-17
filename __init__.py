from binaryninja import user_plugin_path
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import (
    ChoiceField,
    DirectoryNameField,
    OpenFileNameField,
    SaveFileNameField,
    TextLineField,
    get_form_input,
    get_choice_input,
    get_open_filename_input,
    show_message_box,
)
from binaryninja.platform import Platform
from binaryninja.architecture import Architecture
from binaryninja.typelibrary import TypeLibrary
from binaryninja.log import log_info, log_error, log_debug

from pathlib import Path

typelib_path = (Path(user_plugin_path()) / ".." / "typelib").resolve()


def load_platform_libraries():
    try:
        for p in list(Platform):
            path = typelib_path / p.name
            path.mkdir(parents=True, exist_ok=True)

    except IOError:
        log_error("Unable to create {}".format(lib_path))

    for p in typelib_path.iterdir():
        platform = Platform[p.name]

        for typelib_file in p.iterdir():
            tl = TypeLibrary.load_from_file(str(typelib_file))
            platform.type_libraries.append(tl)
            log_info("Loaded type library: {}".format(typelib_file))


def generate_single_platform(bv):
    arch_choices = [i.name for i in list(Platform)]

    header_file = OpenFileNameField("Select Header File")
    arch = ChoiceField("Select Architecture", arch_choices)
    name = TextLineField("Type Library Name")
    save_file = SaveFileNameField("Save Type Library", ext="bntl")
    get_form_input([header_file, arch, name, save_file], "Generate Type Library")

    arch = arch_choices[arch.result]
    platform = Platform[arch]

    try:
        typelib = generate_typelib(platform, header_file.result, name.result)
        typelib.write_to_file(save_file.result)
    except SyntaxError as e:
        show_message_box("Error", e.msg.decode())


def generate_all_platforms(bv):
    platforms = [i.name for i in list(Platform)]

    header_file = OpenFileNameField("Select Header File")
    lib_name = TextLineField("Type Library Name")
    file_name = TextLineField("File Name")
    get_form_input([header_file, lib_name, file_name], "Generate Type Library")

    try:
        for p in list(Platform):
            typelib = generate_typelib(p, header_file.result, lib_name.result)
            path = typelib_path / p.name / "{}.bntl".format(file_name.result)
            typelib.write_to_file(str(path.resolve()))
    except SyntaxError as e:
        show_message_box("Error", e.msg.decode())


def generate_typelib(platform, source_file, typelib_name):
    res = platform.parse_types_from_source_file(source_file)
    typelib = TypeLibrary.new(Architecture[platform.arch.name], typelib_name)

    for name, type_obj in res.functions.items():
        typelib.add_named_object(name, type_obj)

    for name, type_obj in res.types.items():
        typelib.add_named_type(name, type_obj)

    typelib.add_platform(platform)
    typelib.finalize()

    return typelib


def select_typelib(bv):
    libs = bv.platform.type_libraries
    choice = get_choice_input(
        "Select Type Library", "Platform Libraries", [i.name for i in libs]
    )
    bv.add_type_library(libs[choice])


PluginCommand.register(
    "Type Manager: Generate Type Library [Single Platform]",
    "Generate a type library for a single platform.",
    generate_single_platform,
)

PluginCommand.register(
    "Type Manager: Generate Type Library [All Platforms]",
    "Generate a type library for all Binary Ninja platforms.",
    generate_all_platforms,
)

PluginCommand.register(
    "Type Manager: Load Type Library",
    "Load a type library for use in the binary view.",
    select_typelib,
)

load_platform_libraries()
