project('termux-elf-cleaner', 'cpp',
  version : '3.0.1',
  default_options : ['cpp_std=c++20'],
)

add_project_arguments('-DPACKAGE_NAME="termux-elf-cleaner"',
                      '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
                      '-DCOPYRIGHT="Copyright (C) 2022 Termux."',
                      language: 'cpp')

elf_cleaner = executable('termux-elf-cleaner', 'elf-cleaner.cpp',
  dependencies : dependency('threads'),
  install : true,
)

meson.override_find_program('termux-elf-cleaner', elf_cleaner)
