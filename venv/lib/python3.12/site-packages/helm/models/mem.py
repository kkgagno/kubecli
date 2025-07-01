# -*- coding: utf-8 -*-

# Helm
# models/mem.py

# Copyright (C) 2011 Anaël Verrier <elghinn@free.fr>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re

from helm import model


class Mem(model.Model):
    name = 'Mem'
    info_names = ('MemTotal', 'MemFree', 'Buffers', 'Cached', 'Slab')
    res = dict()

    def __init__(self):
        model.Model.__init__(self)
        self.infos = dict()
        self.update_infos()

    @classmethod
    def init_re(cls):
        for name in cls.info_names:
            cls.res[name] = re.compile('%s:\s*(\d+) kB' % name)

    def update(self):
        self.update_infos()
        self._update()

    def _update(self):
        free = (self.infos['MemFree'] + self.infos['Buffers'] +
                self.infos['Cached'])# + self.infos['Slab'])
        self.pct = 1 - float(free) / self.infos['MemTotal']

    def update_infos(self):
        meminfo = open('/proc/meminfo', 'r')
        content = meminfo.read()
        meminfo.close()

        for name in self.info_names:
            self.infos[name] = int(self.res[name].findall(content)[0]) * 1024


class Swap(Mem):
    name = 'Swap'
    info_names = ('SwapCached', 'SwapTotal', 'SwapFree')

    def _update(self):
        free = self.infos['SwapFree'] + self.infos['SwapCached']
        self.pct = 1 - float(free) / self.infos['SwapTotal']


Mem.init_re()
Swap.init_re()
