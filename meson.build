project('termux-elf-cleaner', 'c', 'cpp', version : '2.1.1')

add_project_arguments('-DPACKAGE_NAME="termux-elf-cleaner"',
                      '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
                      '-DCOPYRIGHT="Copyright (C) 2022 Termux."',
                      language: 'cpp')

sources = [
  'elf-cleaner.cpp',
  'arghandling.c',
]
elf_cleaner = executable('termux-elf-cleaner', sources, install : true)

meson.override_find_program('termux-elf-cleaner', elf_cleaner)
