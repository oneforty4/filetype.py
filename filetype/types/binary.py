# -*- coding: utf-8 -*-

from __future__ import absolute_import

from .base import Type

class Elf(Type):
    """Implements the ELF (Executable and Linkable Format) binary matcher."""

    MIME = 'application/x-elf'
    EXTENSION = 'elf'

    def __init__(self):
        super(Elf, self).__init__(
            mime=Elf.MIME,
            extension=Elf.EXTENSION
        )

    def match(self, buf):
        return buf[:4] == bytearray([0x7f, 0x45, 0x4c, 0x46])

class MachO(Type):
    """Implements the Mach-O binary matcher."""

    MIME = 'application/vnd.apple.mach-o'
    EXTENSION = 'mach-o'

    def __init__(self):
        super(MachO, self).__init__(
            mime=MachO.MIME,
            extension=MachO.EXTENSION
        )

    def match(self, buf):
        return (buf[:4] == bytearray([0xcf, 0xfa, 0xed, 0xfe]) or
               buf[:4] == bytearray([0xce, 0xfa, 0xed, 0xfe]) or
               buf[:4] == bytearray([0xca, 0xfe, 0xba, 0xbe]))

class Pe32(Type):
    """Implements the PE32+ Portable Executable binary matcher."""

    MIME = 'application/vnd.microsoft.portable-executable'
    EXTENSION = 'pe32+'

    def __init__(self):
        super(Pe32, self).__init__(
            mime=Pe32.MIME,
            extension=Pe32.EXTENSION
        )

    def match(self, buf):
        return buf[:2] == bytearray([0x4d, 0x5a])
